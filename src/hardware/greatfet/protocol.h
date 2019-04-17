/*
 * This file is part of the libsigrok project.
 *
 * Copyright (C) 2019 Katherine J. Temkin <k@ktemkin.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef LIBSIGROK_HARDWARE_GREATFET_PROTOCOL_H
#define LIBSIGROK_HARDWARE_GREATFET_PROTOCOL_H

#include <stdint.h>
#include <libusb.h>

#include <libsigrok/libsigrok.h>
#include "libsigrok-internal.h"

#define LOG_PREFIX "greatfet"

// The default USB parameters for a normal GreatFET.
#define GREATFET_VID_PID                       "1d50.60e6"
#define GREATFET_USB_INTERFACE                 (0)

// Parameters of the allocated transfers.
#define GREATFET_TRANSFER_POOL_SIZE            (32)
#define GREATFET_TRANSFER_BUFFER_SIZE          (262144)

#define GREATFET_LOGIC_MAX_DATA_OUT            (512)
#define GREATFET_LOGIC_MAX_STRING_LENGTH       (128)
#define GREATFET_LOGIC_DEFAULT_TIMEOUT         (1000)

#define GREATFET_LIBGREAT_REQUEST_NUMBER       (0x65)
#define GREATFET_LIBGREAT_VALUE_EXECUTE        (0)
#define GREATFET_LIBGREAT_VALUE_CANCEL         (0xDEAD)
#define GREATFET_LIBGREAT_FLAG_SKIP_RESPONSE   (1 << 0)

// GreatFET class numbers.
#define GREATFET_CLASS_CORE                    (0x000)
#define GREATFET_CLASS_LA                      (0x10D)

// Board identification functions.
#define GREATFET_CORE_VERB_READ_VERSION        (0x1)
#define GREATFET_CORE_VERB_READ_SERIAL         (0x3)

// Logic analyzer functions.
#define GREATFET_LA_VERB_START                 (0x0)
#define GREATFET_LA_VERB_STOP                  (0x1)


/**
 *  Structure that contains the 
 */
struct greatfet_context {

    uint8_t endpoint;
    gboolean acquisition_active;

    // Transfer pool that stores asynchronous usb bulk transfers.
    struct libusb_transfer *transfers[GREATFET_TRANSFER_POOL_SIZE];

    // Total buffer to store our samples as they're asynchronously loaded via USB.
    uint8_t buffer[GREATFET_TRANSFER_POOL_SIZE * GREATFET_TRANSFER_BUFFER_SIZE];

    // Configuration state.
    uint64_t sample_rate;
    uint32_t num_channels;

    // Limits of the current capture.
    uint64_t samples_captured;
    uint64_t capture_limit_samples;
};

/**
 * @returns a string containing the analyzer version, or NULL if one can't be read.
 *    Should be freed with g_free when complete.
 */
char *greatfet_get_version_number(struct sr_dev_inst *device);

/**
 * @returns a string containing the analyzer version, or NULL if one can't be read.
 *    Should be freed with g_free when complete.
 */
char *greatfet_get_serial_number(struct sr_dev_inst *device);


// Transfer management functions.
int greatfet_allocate_transfers(struct sr_dev_inst *device);
int greatfet_cancel_transfers(struct sr_dev_inst *device);
int greatfet_prepare_transfers(const struct sr_dev_inst *device, libusb_transfer_cb_fn callback);
int greatfet_free_transfers(struct greatfet_context *context);

// High level control functions.
int greatfet_start_acquire(const struct sr_dev_inst *device);
int greatfet_stop_acquire(const struct sr_dev_inst *device);


#endif
