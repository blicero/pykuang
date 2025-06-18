// Time-stamp: <2025-06-05 18:41:55 krylon>
// -*- mode: javascript; coding: utf-8; -*-
// Copyright 2015-2020 Benjamin Walkenhorst <krylon@gmx.net>
//
// This file has grown quite a bit larger than I had anticipated.
// It is not a /big/ problem right now, but in the long run, I will have to
// break this thing up into several smaller files.

'use strict';

function defined(x) {
    return undefined !== x && null !== x
}

function fmtDateNumber(n) {
    return (n < 10 ? '0' : '') + n.toString()
} // function fmtDateNumber(n)

function timeStampString(t) {
    if ((typeof t) === 'string') {
        return t
    }

    const year = t.getYear() + 1900
    const month = fmtDateNumber(t.getMonth() + 1)
    const day = fmtDateNumber(t.getDate())
    const hour = fmtDateNumber(t.getHours())
    const minute = fmtDateNumber(t.getMinutes())
    const second = fmtDateNumber(t.getSeconds())

    const s =
          year + '-' + month + '-' + day +
          ' ' + hour + ':' + minute + ':' + second
    return s
} // function timeStampString(t)

function fmtDuration(seconds) {
    let minutes = 0
    let hours = 0

    while (seconds > 3599) {
        hours++
        seconds -= 3600
    }

    while (seconds > 59) {
        minutes++
        seconds -= 60
    }

    if (hours > 0) {
        return `${hours}h${minutes}m${seconds}s`
    } else if (minutes > 0) {
        return `${minutes}m${seconds}s`
    } else {
        return `${seconds}s`
    }
} // function fmtDuration(seconds)

function beaconLoop() {
    try {
        if (settings.beacon.active) {
            const req = $.get('/ajax/beacon',
                              {},
                              function (response) {
                                  let status = ''

                                  if (response.Status) {
                                      status = 
                                          response.Message +
                                          ' running on ' +
                                          response.Hostname +
                                          ' is alive at ' +
                                          response.Timestamp
                                  } else {
                                      status = 'Server is not responding'
                                  }

                                  const beaconDiv = $('#beacon')[0]

                                  if (defined(beaconDiv)) {
                                      beaconDiv.innerHTML = status
                                      beaconDiv.classList.remove('error')
                                  } else {
                                      console.log('Beacon field was not found')
                                  }
                              },
                              'json'
                             ).fail(function () {
                                 const beaconDiv = $('#beacon')[0]
                                 beaconDiv.innerHTML = 'Server is not responding'
                                 beaconDiv.classList.add('error')
                                 // logMsg("ERROR", "Server is not responding");
                             })
        }
    } finally {
        window.setTimeout(beaconLoop, settings.beacon.interval)
    }
} // function beaconLoop()

function beaconToggle() {
    settings.beacon.active = !settings.beacon.active
    saveSetting('beacon', 'active', settings.beacon.active)

    if (!settings.beacon.active) {
        const beaconDiv = $('#beacon')[0]
        beaconDiv.innerHTML = 'Beacon is suspended'
        beaconDiv.classList.remove('error')
    }
} // function beaconToggle()

function toggle_hide_boring() {
    const state = !settings.news.hideBoring
    settings.news.hideBoring = state
    saveSetting('news', 'hideBoring', state)
    $("#toggle_hide_boring")[0].checked = state
} // function toggle_hide_boring()

/*
  The ‘content’ attribute of Window objects is deprecated.  Please use ‘window.top’ instead. interact.js:125:8
  Ignoring get or set of property that has [LenientThis] because the “this” object is incorrect. interact.js:125:8

*/

function db_maintenance() {
    const maintURL = '/ajax/db_maint'

    const req = $.get(
        maintURL,
        {},
        function (res) {
            if (!res.Status) {
                console.log(res.Message)
                postMessage(new Date(), 'ERROR', res.Message)
            } else {
                const msg = 'Database Maintenance performed without errors'
                console.log(msg)
                postMessage(new Date(), 'INFO', msg)
            }
        },
        'json'
    ).fail(function () {
        const msg = 'Error performing DB maintenance'
        console.log(msg)
        postMessage(new Date(), 'ERROR', msg)
    })
} // function db_maintenance()

function scale_images() {
    const selector = '#items img'
    const maxHeight = 300
    const maxWidth = 300

    $(selector).each(function () {
        const img = $(this)[0]
        if (img.width > maxWidth || img.height > maxHeight) {
            const size = shrink_img(img.width, img.height, maxWidth, maxHeight)

            img.width = size.width
            img.height = size.height
        }
    })
} // function scale_images()

// Found here: https://stackoverflow.com/questions/3971841/how-to-resize-images-proportionally-keeping-the-aspect-ratio#14731922
function shrink_img(srcWidth, srcHeight, maxWidth, maxHeight) {
    const ratio = Math.min(maxWidth / srcWidth, maxHeight / srcHeight)

    return { width: srcWidth * ratio, height: srcHeight * ratio }
} // function shrink_img(srcWidth, srcHeight, maxWidth, maxHeight)

const max_msg_cnt = 5

function msg_clear() {
    $('#msg_tbl')[0].innerHTML = ''
} // function msg_clear()

function msg_add(msg, level=1) {
    const row = `<tr><td>${new Date()}</td><td>${level}</td><td>${msg}</td><td></td></tr>`
    const msg_tbl = $('#msg_tbl')[0]

    const rows = $('#msg_tbl tr')
    let i = 0
    let cnt = rows.length
    while (cnt >= max_msg_cnt) {
        rows[i].remove()
        i++
        cnt--
    }

    msg_tbl.innerHTML += row
} // function msg_add(msg)

function fmtNumber(n, kind = "") {
    if (kind in formatters) {
        return formatters[kind](n)
    } else {
        return fmtDefault(n)
    }
}

function fmtDefault(n) {
    return n.toPrecision(3).toString()
}

function fmtBytes(n) {
    const units = ["KB", "MB", "GB", "TB", "PB"]
    let idx = 0
    while (n >= 1024) {
        n /= 1024
        idx++
    }

    return `${n.toPrecision(3)} ${units[idx]}`
}

const formatters = {
    "sysload": fmtNumber,
    "disk": fmtBytes,
}
