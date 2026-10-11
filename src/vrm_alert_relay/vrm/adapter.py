"""Fetch VRM Diagnostics through :class:`SafeHttpClient` and normalise them.

One ``GET {base}/installations/{site_id}/diagnostics?count=1000`` is sent per
installation per poll, authenticated with ``X-Authorization: Token <token>``.
The base URL comes only from configuration (HTTPS, validated by
:class:`Endpoint`). The token and the full header value are registered with
the log redaction registry when the adapter is built.

The adapter never sleeps and never hides a failure: every installation in a
poll yields either a reading or a typed :class:`VrmError`, and a reading
carries a typed problem for each measurement that produced no sample. The
caller (the scheduler) decides poll timing from :class:`PollResult` and the
inspectable :class:`Backoff`.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Final, NoReturn

from vrm_alert_relay.config.models import DEFAULT_VRM_BASE_URL
from vrm_alert_relay.logs.redaction import SecretRegistry, register_derived_secret, register_secret
from vrm_alert_relay.net.endpoint import Endpoint
from vrm_alert_relay.net.errors import (
    HttpContentEncodingRefused,
    HttpDecodeError,
    HttpError,
    HttpRedirectRefused,
    HttpStatusError,
    HttpTimeout,
    HttpTooLarge,
    HttpTransportError,
)
from vrm_alert_relay.vrm.backoff import Backoff
from vrm_alert_relay.vrm.diagnostics import (
    MAX_RECORDS,
    MeasurementResult,
    TimestampPolicy,
    parse_diagnostics,
)
from vrm_alert_relay.vrm.errors import (
    VrmAuthError,
    VrmError,
    VrmRateLimitedError,
    VrmRejectedError,
    VrmResponseError,
    VrmUnavailableError,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from vrm_alert_relay.config.models import Installation, Measurement, VrmConfig
    from vrm_alert_relay.config.secret import Secret
    from vrm_alert_relay.net.client import SafeHttpClient

DIAGNOSTICS_COUNT: Final = MAX_RECORDS
DEFAULT_MAX_RESPONSE_BYTES: Final = 2 * 1024 * 1024
AUTH_HEADER: Final = "X-Authorization"

_UNAUTHORIZED: Final = 401
_FORBIDDEN: Final = 403
_REQUEST_TIMEOUT: Final = 408
_TOO_MANY_REQUESTS: Final = 429
_SERVER_ERROR: Final = 500

_log = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class InstallationReading:
    """Normalised results for one installation, in the order requested."""

    installation: Installation
    results: tuple[MeasurementResult, ...]
    fetched_at: datetime

    def result_for(self, measurement: Measurement) -> MeasurementResult | None:
        return next((r for r in self.results if r.measurement == measurement), None)

    @property
    def problems(self) -> tuple[MeasurementResult, ...]:
        return tuple(r for r in self.results if not r.ok)


@dataclass(frozen=True, slots=True)
class InstallationOutcome:
    """A reading or a failure for one installation in a poll.

    ``deferred`` is true when no request was sent because the installation is
    backing off; ``error`` is then the failure that caused it. ``retry_at`` is
    the monotonic time from which the installation may be fetched again, or
    ``None`` after a success.
    """

    installation: Installation
    reading: InstallationReading | None = None
    error: VrmError | None = None
    deferred: bool = False
    retry_at: float | None = None

    def __post_init__(self) -> None:
        if (self.reading is None) == (self.error is None):
            raise ValueError("exactly one of reading and error must be set")  # noqa: TRY003  # message is specific to this check

    @property
    def ok(self) -> bool:
        return self.reading is not None


@dataclass(frozen=True, slots=True)
class PollResult:
    """Every installation's outcome for one poll, in the order requested."""

    outcomes: tuple[InstallationOutcome, ...]

    @property
    def failures(self) -> tuple[InstallationOutcome, ...]:
        return tuple(o for o in self.outcomes if not o.ok)

    @property
    def degraded(self) -> bool:
        """Whether any installation failed or any measurement produced no sample."""
        return any(o.reading is None or o.reading.problems for o in self.outcomes)

    @property
    def next_attempt_at(self) -> float | None:
        """The earliest monotonic time a failed installation may be retried."""
        times = [o.retry_at for o in self.outcomes if o.retry_at is not None]
        return min(times) if times else None


class VrmAdapter:
    """Polls VRM Diagnostics for configured installations. See the module docstring."""

    __slots__ = (
        "_backoff",
        "_base",
        "_clock",
        "_http",
        "_max_response_bytes",
        "_timestamps",
        "_token",
        "_wall_clock",
    )

    def __init__(  # noqa: PLR0913  # keyword-only collaborators, injectable for tests
        self,
        http: SafeHttpClient,
        token: Secret,
        *,
        base_url: str = DEFAULT_VRM_BASE_URL,
        backoff: Backoff | None = None,
        timestamp_policy: TimestampPolicy | None = None,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], datetime] = _utcnow,
        registry: SecretRegistry | None = None,
    ) -> None:
        if (
            isinstance(max_response_bytes, bool)
            or not isinstance(max_response_bytes, int)
            or max_response_bytes < 1
        ):
            raise ValueError("max_response_bytes must be a positive integer")  # noqa: TRY003  # message is specific to this check
        self._base = Endpoint(base_url)
        value = token.reveal()
        header = f"Token {value}"
        if registry is None:
            register_secret(value)
            register_derived_secret(header)
        else:
            registry.register(value)
            registry.register(header)
        self._http = http
        self._token = token
        self._backoff = backoff if backoff is not None else Backoff()
        self._timestamps = timestamp_policy if timestamp_policy is not None else TimestampPolicy()
        self._max_response_bytes = max_response_bytes
        self._clock = clock
        self._wall_clock = wall_clock

    @classmethod
    def from_config(
        cls,
        config: VrmConfig,
        token: Secret,
        http: SafeHttpClient,
        *,
        backoff: Backoff | None = None,
    ) -> VrmAdapter:
        """Build an adapter for ``config.base_url`` with the token read from its file."""
        return cls(http, token, base_url=config.base_url, backoff=backoff)

    @property
    def backoff(self) -> Backoff:
        return self._backoff

    def __repr__(self) -> str:
        return f"VrmAdapter({self._base.display!r})"

    def __reduce__(self) -> NoReturn:
        raise TypeError("VrmAdapter cannot be pickled")  # noqa: TRY003  # message is specific to this check

    def fetch(
        self, installation: Installation, measurements: Sequence[Measurement]
    ) -> InstallationReading:
        """Send one Diagnostics request and normalise it. Ignores backoff.

        Raises :class:`VrmError` for any failure of the request or response.
        """
        endpoint = self._base.join("installations", installation.site_id, "diagnostics")
        try:
            response = self._http.get(
                endpoint,
                params={"count": DIAGNOSTICS_COUNT},
                headers={AUTH_HEADER: f"Token {self._token.reveal()}"},
                max_response_bytes=self._max_response_bytes,
            )
            payload = response.json()
        except HttpError as exc:
            error = _translate(exc, installation.id)
        else:
            now = self._wall_clock()
            results = parse_diagnostics(
                payload,
                measurements,
                installation=installation.id,
                now=now,
                policy=self._timestamps,
            )
            return InstallationReading(installation, results, now)
        # Raised outside the except block so it has no __context__.
        raise error

    def poll(self, targets: Sequence[tuple[Installation, Sequence[Measurement]]]) -> PollResult:
        """Fetch every installation that is not backing off and record the outcomes.

        After a 429 the remaining installations in the poll are deferred,
        because the rate limit applies to the token.
        """
        outcomes: list[InstallationOutcome] = []
        for installation, measurements in targets:
            key = installation.id
            blocked = self._backoff.blocking_error(key, self._clock())
            if blocked is not None:
                outcomes.append(
                    InstallationOutcome(
                        installation,
                        error=blocked,
                        deferred=True,
                        retry_at=self._backoff.retry_at(key),
                    )
                )
                continue
            try:
                reading = self.fetch(installation, measurements)
            except VrmError as exc:
                retry_at = self._backoff.record_failure(key, exc, self._clock())
                _log.warning(
                    "vrm fetch failed",
                    extra={
                        "vrm_installation": key,
                        "vrm_failure": exc.kind.value,
                        "vrm_detail": exc.detail,
                    },
                )
                outcomes.append(InstallationOutcome(installation, error=exc, retry_at=retry_at))
            else:
                self._backoff.record_success(key)
                outcomes.append(InstallationOutcome(installation, reading=reading))
        return PollResult(tuple(outcomes))


def _translate(exc: HttpError, installation: str) -> VrmError:  # noqa: PLR0911  # one return per error class
    if isinstance(exc, HttpStatusError):
        return _translate_status(exc, installation)
    if isinstance(exc, HttpTimeout):
        return VrmUnavailableError(installation, f"timeout ({exc.phase})")
    if isinstance(exc, HttpTransportError):
        return VrmUnavailableError(installation, f"connection failed ({exc.cause})")
    if isinstance(exc, HttpRedirectRefused):
        return VrmResponseError(installation, f"unexpected redirect (HTTP {exc.status})")
    if isinstance(exc, HttpTooLarge):
        return VrmResponseError(installation, f"response exceeded {exc.limit} bytes")
    if isinstance(exc, HttpContentEncodingRefused):
        return VrmResponseError(installation, "compressed response refused")
    if isinstance(exc, HttpDecodeError):
        return VrmResponseError(installation, "response is not valid JSON")
    return VrmRejectedError(installation, "request could not be built")


def _translate_status(exc: HttpStatusError, installation: str) -> VrmError:
    status = exc.status
    if status in {_UNAUTHORIZED, _FORBIDDEN}:
        return VrmAuthError(installation, status=status)
    if status == _TOO_MANY_REQUESTS:
        return VrmRateLimitedError(installation, retry_after=exc.retry_after)
    if status >= _SERVER_ERROR or status == _REQUEST_TIMEOUT:
        return VrmUnavailableError(installation, f"HTTP {status}", status=status)
    return VrmRejectedError(installation, f"HTTP {status}", status=status)
