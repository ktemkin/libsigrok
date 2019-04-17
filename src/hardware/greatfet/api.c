/*
 * This file is part of the libsigrok project.
 *
 * Copyright (C) 2019 Katherine J. Temkin <k@ktemkin.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */


#include <libsigrok/libsigrok.h>

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdint.h>

#include "libsigrok-internal.h"
#include "protocol.h"

static int dev_acquisition_stop(struct sr_dev_inst *device);

#define DEFAULT_NUM_LOGIC_CHANNELS (8)
#define DEFAULT_SAMPLE_RATE SR_MHZ(17)

static const uint32_t scanopts[] = {
	SR_CONF_NUM_LOGIC_CHANNELS,
	SR_CONF_CONN,
};

static const uint32_t driver_options[] = {
	SR_CONF_LOGIC_ANALYZER,
//	TODO: SR_CONF_OSCILLOSCOPE for ADC?
};

static const uint64_t greatfet_samplerates[] = { 
	SR_MHZ(17),
	SR_KHZ(40800),
	SR_MHZ(51),
	SR_MHZ(68),
	SR_MHZ(102),
	SR_MHZ(204)
};
static const uint32_t greatfet_channels[]    = { 1, 2, 4, 8, 16 };

static const char *greatfet_channel_names[] = {
	"SGPIO0",  "SGPIO1",  "SGPIO2",  "SGPIO3",
	"SGPIO4",  "SGPIO5",  "SGPIO6",  "SGPIO7",
	"SGPIO8",  "SGPIO9",  "SGPIO10", "SGPIO11",
	"SGPIO12", "SGPIO13", "SGPIO14", "SGPIO15"
};

/*
	Possible things to add:

	SR_CONF_LIMIT_MSEC | SR_CONF_GET | SR_CONF_SET,
	SR_CONF_LIMIT_FRAMES | SR_CONF_GET | SR_CONF_SET,
	SR_CONF_AVERAGING | SR_CONF_GET | SR_CONF_SET,
	SR_CONF_AVG_SAMPLES | SR_CONF_GET | SR_CONF_SET,
	SR_CONF_TRIGGER_MATCH | SR_CONF_LIST,
	SR_CONF_CAPTURE_RATIO | SR_CONF_GET | SR_CONF_SET,
*/
static const uint32_t device_options[] = {
	SR_CONF_CONTINUOUS,
	SR_CONF_NUM_LOGIC_CHANNELS | SR_CONF_GET | SR_CONF_SET | SR_CONF_LIST,
	SR_CONF_SAMPLERATE | SR_CONF_GET | SR_CONF_SET | SR_CONF_LIST,
	SR_CONF_LIMIT_SAMPLES | SR_CONF_GET | SR_CONF_SET,
};


/**
 * Scan for any attached (and relevant) GreatFET devices.
 */ 
static GSList *scan(struct sr_dev_driver *driver, GSList *options)
{
	unsigned i;

	struct drv_context      *driver_context = driver->context;

	GSList *usb_devices, *devices, *usb_device;
	struct sr_dev_inst      *device;
	struct greatfet_context *context;
	struct sr_usb_dev_inst  *connection;

    // TODO: support parsing e.g. libgreat connection URI to be able to select a device e.g. by serial
	(void)options;

	devices = NULL;

    // Find all GreatFET devices.
	usb_devices = sr_usb_find(driver_context->sr_ctx->libusb_ctx, GREATFET_VID_PID);

    // If we can't find any GreatFETs, return them.
	if (!usb_devices)
		return NULL;

    // Iterate over all devices that match the GreatFET VID/PID, get their information,
    // and filter out ones that don't support logic analyzer modes.
	for (usb_device = usb_devices; usb_device; usb_device = usb_device->next) {
		connection = usb_device->data;

        // Allocate the sigrok and local data structures.
		device                = g_malloc0(sizeof(struct sr_dev_inst));
		context               = g_malloc0(sizeof(struct greatfet_context));
		device->priv          = context;

		// Store our local USB connection.
		device->conn          = usb_device->data;
		device->inst_type     = SR_INST_USB;

        // Mark our fresh device as not yet used.
		device->status        = SR_ST_INACTIVE;

		// Allocate the buffers associated with the given device.
		greatfet_allocate_transfers(device);

		// Open the USB device temporarily, so we can acecss its properties.
		if (sr_usb_open(driver_context->sr_ctx->libusb_ctx, connection) != SR_OK) {
			continue;
		}

        // FIXME: Fetch this information from the GreatFET.
		device->vendor        = g_strdup("Great Scott Gadgets");
		device->model         = g_strdup("GreatFET One/Azalea");
		device->version       = greatfet_get_version_number(device);
		device->serial_num    = greatfet_get_serial_number(device);

		sr_usb_close(connection);

		if (!device->version) {
			device->version =  g_strdup("(unknown version)");
		}

		// If we have a serial number, convert it to a unique connection ID.
		if (device->serial_num) {
			device->connection_id = g_strdup(device->serial_num);
		} else {
			device->serial_num =  g_strdup("(unknown serial)");
		}

		// Set up the initial configuration.
		context->num_channels = DEFAULT_NUM_LOGIC_CHANNELS;
		context->sample_rate  = DEFAULT_SAMPLE_RATE;

		// FIXME: Read the sample endpoint from the GreatFET.
		context->endpoint    = 0x81;

		// Set up the device's channels.
		for (i = 0; i < ARRAY_SIZE(greatfet_channel_names); ++i) {
			const char *name = greatfet_channel_names[i];
			sr_channel_new(device, i, SR_CHANNEL_LOGIC, i < 8, name);
		}

		devices = g_slist_append(devices, device);
	}

	g_slist_free(usb_devices);

	return std_scan_complete(driver, devices);
}

/**
 * Opens a new GreatFET connection.
 */ 
static int dev_open(struct sr_dev_inst *device)
{
	int ret;

	struct sr_dev_driver    *driver         = device->driver;
	struct drv_context      *driver_context = driver->context;
	struct sr_usb_dev_inst  *connection     = device->conn;

	// Open the backing USB device.
	if (sr_usb_open(driver_context->sr_ctx->libusb_ctx, connection) != SR_OK) {
		return SR_ERR;
	}

    // FIXME: handle configuration / detaching kernel drivers / etc

	// Claim the interface we'll be using to communicate with the GreatFET.
	if ((ret = libusb_claim_interface(connection->devhdl, GREATFET_USB_INTERFACE)) < 0) {
		sr_err("Failed to claim interface: %s.", libusb_error_name(ret));
		return SR_ERR;
	}

	return SR_OK;
}


/**
 * Closes a GreatFET connection.
 */
static int dev_close(struct sr_dev_inst *device)
{
	struct sr_usb_dev_inst *connection = device->conn;

	if (!connection->devhdl)
		return SR_ERR_BUG;


	libusb_release_interface(connection->devhdl, GREATFET_USB_INTERFACE);
	libusb_close(connection->devhdl);

	connection->devhdl = NULL;
	return SR_OK;
}


static void clear_helper(struct greatfet_context *context)
{
	greatfet_free_transfers(context);
}


static int dev_clear(const struct sr_dev_driver *device)
{
	return std_dev_clear_with_callback(device, (std_dev_clear_callback)clear_helper);
}


static int config_get(uint32_t key, GVariant **data,
	const struct sr_dev_inst *device, const struct sr_channel_group *cg)
{
	struct greatfet_context *context = device->priv;
	(void)cg;

	switch (key) {
		case SR_CONF_SAMPLERATE:
			*data = g_variant_new_uint64(context->sample_rate);
			break;

		case SR_CONF_NUM_LOGIC_CHANNELS:
			*data = g_variant_new_uint32(context->num_channels);
			break;

		case SR_CONF_LIMIT_SAMPLES:
			*data = g_variant_new_uint64(context->capture_limit_samples);
			break;

		default:
			return SR_ERR_NA;
	}

	return SR_OK;
}

static int config_set(uint32_t key, GVariant *data,
	const struct sr_dev_inst *device, const struct sr_channel_group *cg)
{
	struct greatfet_context *context = device->priv;
	(void)cg;

	switch (key) {

		case SR_CONF_SAMPLERATE:
			context->sample_rate = g_variant_get_uint64(data);
			// TODO: validate?
			return SR_OK;

		case SR_CONF_NUM_LOGIC_CHANNELS:
			context->num_channels = g_variant_get_uint32(data);
			return SR_OK;

		case SR_CONF_LIMIT_SAMPLES:
			context->capture_limit_samples = g_variant_get_uint64(data);
			break;

		default:
			return SR_ERR_NA;
	}

	return SR_OK;
}

static int config_list(uint32_t key, GVariant **data, 
	const struct sr_dev_inst *device, const struct sr_channel_group *channel_group)
{

	switch (key) {

		case SR_CONF_SCAN_OPTIONS:
		case SR_CONF_DEVICE_OPTIONS:
			return STD_CONFIG_LIST(key, data, device, channel_group, 
				scanopts, driver_options, device_options);

		case SR_CONF_SAMPLERATE:
			*data = std_gvar_samplerates(ARRAY_AND_SIZE(greatfet_samplerates));
			break;

		case SR_CONF_NUM_LOGIC_CHANNELS:
			*data = std_gvar_array_u32(ARRAY_AND_SIZE(greatfet_channels));
			break;

		default:
			return SR_ERR_NA;

	}

	return SR_OK;
}

/**
 * Submits the included samples to the Sigrok core for copying/processing.
 */ 
static void submit_samples(struct sr_dev_inst *device, uint8_t *data, size_t length)
{
	struct greatfet_context *context  = device->priv;
	uint8_t unit_size = (context->num_channels > 8) ? 2 : 1;

	uint64_t samples_submitted = length / unit_size;

	const struct sr_datafeed_logic logic = {
		.length = length,
		.unitsize = unit_size,
		.data = data
	};

	const struct sr_datafeed_packet packet = {
		.type = SR_DF_LOGIC,
		.payload = &logic
	};

	// Submit the samples themselves to the sigrok core.
	sr_session_send(device, &packet);

	// And keep track of how long we've been sampling for.
	context->samples_captured += samples_submitted;
}

static gboolean transfer_should_stop(struct sr_dev_inst *device)
{
	struct greatfet_context *context  = device->priv;

	// If we've met our capture goal, it's time to stop.
	if (context->capture_limit_samples) {
		if (context->samples_captured >= context->capture_limit_samples) {
			sr_dbg("Met sample goal with %" PRIu64"  samples (trying for %" PRIu64 ")\n",
				context->samples_captured, context->capture_limit_samples);
			return TRUE;
		}
	}

	// If none of the above conditions are true, we should continue sampling.
	return FALSE;
}

/**
 * Asynchronous callback called by libusb when one of our sample-acquisition transfers completes.
 */
static void LIBUSB_CALL sample_transfer_complete(struct libusb_transfer *transfer)
{
	int rc;

	struct sr_dev_inst *device = transfer->user_data;
	struct greatfet_context *context  = device->priv;

	// If we're not actively trying to acquire anything, ignore the data we've received.
	if (!context->acquisition_active) {
		return;
	}

	sr_dbg("sample_transfer_complete(): status %s; received %d bytes.",
		libusb_error_name(transfer->status), transfer->actual_length);


	// Handle the various ways that a transfer could have ended.
	switch (transfer->status) {
	
		// If the transfer timed out, we may have gotten some data, but not all of the data we wanted.
		// Process the data we have, but emit a warning.
		case LIBUSB_TRANSFER_TIMED_OUT:
			sr_warn("%s(): transfer timed out; trying to use what data we received\n",  __func__);
			// Fall through to sample consumption.

		// Handle normal sample consumption.
		case LIBUSB_TRANSFER_COMPLETED:
			submit_samples(device, transfer->buffer, transfer->actual_length);
			break;

		// Handle cases where the other side has stalled the endpoint; which is used to indicate that we're not
		// reading data fast enough from the GreatFET, and its buffer has overrun.
		case LIBUSB_TRANSFER_STALL:
			sr_warn("%s(): the greatfet reports overrun; this sample rate may not be meetable! (trying to continue)\n");
			// TODO: do we need to clear the stall, here?
			break;

		// If the device detached during the process, stop the acquire with a custom message.
		case LIBUSB_TRANSFER_NO_DEVICE:
			sr_err("%s(): transfer terminated due to device detach\n", __func__);
			// Fall through to default error handler.

		default:
			sr_err("%s(): transfer failed (%s), bailing out\n", __func__, libusb_error_name(transfer->status));
			dev_acquisition_stop(device);
			return;

	}

	// Check our sampling limitations and determine if our sample should stop.
	if (transfer_should_stop(device)) {
		dev_acquisition_stop(device);
		return;
	}

	// Re-submit the transfer, so our buffer can be used for future sampling.
	rc = libusb_submit_transfer(transfer);
	if (rc < 0) {
		sr_err("%s(): resubmitting transfer failed (%s), bailing out\n", __func__, libusb_error_name(rc));
		dev_acquisition_stop(device);
		return;
	}
}


static int receive_data(int fd, int revents, void *cb_data)
{
	struct timeval tv;
	struct drv_context *driver_context = (struct drv_context *)cb_data;

	(void)fd;
	(void)revents;

	tv.tv_sec = tv.tv_usec = 0;
	libusb_handle_events_timeout(driver_context->sr_ctx->libusb_ctx, &tv);

	return TRUE;
}

/**
 * Starts acquiring samples from the GreatFET.
 */ 
static int dev_acquisition_start(const struct sr_dev_inst *device)
{
	int rc; 
	struct greatfet_context *context  = device->priv;
	struct drv_context *driver_context = device->driver->context;

	// Mark ourselves as currently sampling.
	context->acquisition_active = TRUE;

	// Start our sample timings over.
	context->samples_captured = 0;

	// Let the Sigrok core know we're going to be providing data via USB.
	// This allows it to periodically call libusb's event handler.
	usb_source_add(device->session, driver_context->sr_ctx, 
		GREATFET_LOGIC_DEFAULT_TIMEOUT, receive_data, driver_context);
	std_session_send_df_header(device);

	rc = greatfet_start_acquire(device);
	greatfet_prepare_transfers(device, sample_transfer_complete);

	return rc;
}



/**
 * Terminates acquisition of samples. Can be called by either Sigrok,
 * or by our internal code.
 */
static int dev_acquisition_stop(struct sr_dev_inst *device)
{
	struct drv_context *driver_context = device->driver->context;
	struct greatfet_context *context  = device->priv;

	if (!context->acquisition_active) {
		return SR_OK;
	}

	// Mark ourselves as no longer actively sampling.
	context->acquisition_active = FALSE;

	std_session_send_df_end(device);
	usb_source_remove(device->session, driver_context->sr_ctx);

	greatfet_cancel_transfers(device);
	return greatfet_stop_acquire(device);
}

static struct sr_dev_driver greatfet_driver_info = {
	.name                   = "greatfet",
	.longname               = "GreatFET",
	.api_version            = 1,

	.init                   = std_init,
	.cleanup                = std_cleanup,

	.scan                   = scan,

	.dev_list               = std_dev_list,
	.dev_clear              = dev_clear,

	.config_get             = config_get,
	.config_set             = config_set,
	.config_list            = config_list,

	.dev_open               = dev_open,
	.dev_close              = dev_close,
	.dev_acquisition_start  = dev_acquisition_start,
	.dev_acquisition_stop   = dev_acquisition_stop,

	.context                = NULL,
};
SR_REGISTER_DEV_DRIVER(greatfet_driver_info);
