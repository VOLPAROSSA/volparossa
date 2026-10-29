# SPDX-License-Identifier: GPL-3.0-only
"""Public synthetic NMEA. Not a device recording or accuracy reference."""
from datetime import datetime, timedelta, timezone


def sentence(body):
    raw = body.encode('ascii')
    if len(raw) > 240 or b'\r' in raw or b'\n' in raw or b'*' in raw or b'$' in raw:
        raise ValueError('invalid bounded synthetic NMEA body')
    checksum = 0
    for byte in raw:
        checksum ^= byte
    return b'$' + raw + ('*%02X\r\n' % checksum).encode('ascii')


def fixture(now, scenario='positive'):
    if now.tzinfo != timezone.utc or scenario not in {'positive', 'unknown_datum', 'missing_height'}:
        raise ValueError('explicit UTC and allowlisted public scenario required')
    # The exact coordinates are intentionally public/artificial: equator,
    # prime meridian, 10m above the ellipsoid. Never a developer/device fix.
    result = bytearray(b'# Date: ' + now.strftime('%Y-%m-%d').encode() + b'\n')
    for lag in (3, 2, 1):
        epoch = now - timedelta(seconds=lag)
        # Preserve the original past UTC, flooring by less than 10ms. Whole-second
        # truncation needlessly spent up to 999ms of the product's 5s age bound.
        hhmmss = epoch.strftime('%H%M%S') + '.%02d' % (epoch.microsecond // 10000)
        date = epoch.strftime('%d%m%y')
        result.extend(sentence('GPZDA,' + hhmmss + epoch.strftime(',%d,%m,%Y,00,00')))
        # GPSD's PASHR,POS parser consumes field9 directly as WGS84 HAE.
        # A GGA positive would instead exercise MSL/geoid conversion.
        height = '' if scenario == 'missing_height' else '10.0'
        fields = ['PASHR', 'POS', '0', '08', hhmmss, '0000.0000', 'N',
                  '00000.0000', 'E', height, '', '0.0', '0.0', '0.0',
                  '1.0', '1.0', '1.0', '1.0']
        result.extend(sentence(','.join(fields)))
        datum = 'W72' if scenario == 'unknown_datum' else 'W84'
        result.extend(sentence('GPDTM,' + datum + ',,0.0,N,0.0,E,0.0,' + datum))
        result.extend(sentence('GPRMC,' + hhmmss + ',A,0000.0000,N,00000.0000,E,0.0,0.0,' + date + ',,,A'))
    if len(result) > 4096:
        raise ValueError('public fixture bound')
    return bytes(result)


def fresh_fixture(scenario='positive'):
    return fixture(datetime.now(timezone.utc), scenario)
