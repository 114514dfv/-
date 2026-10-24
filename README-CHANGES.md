# DroidVM feature sources

Snapshot of the sources changed for the virtual USB camera, the TPM/Secure Boot
firmware support and the VPU (V4L2) passthrough hook.

## crosvm

### Virtual UVC camera (`devices/src/usb/backend/uvc_backend/`)
* `uvc_backend` is a USB Video Class 1.1 MJPEG camera fed by the phone's Camera2
  stack, attached to crosvm's xHCI emulation (`device_provider.rs`,
  `xhci/device_slot.rs` register it alongside the FIDO/host backends).
* `descriptors.rs` - device/configuration descriptors: 1080p/720p/VGA frame
  descriptors, 30 and 60 fps intervals, bulk IN endpoint in streaming alternate
  setting 0 (Windows `usbvideo` rolls back `SET_INTERFACE(1)` on this backend, so
  the endpoint has to live in alt 0), optional SuperSpeed layout, and
  `MAX_PAYLOAD_TRANSFER_SIZE` used for the probe/commit payload size.
* `uvc_device.rs` - control request handling (UVC probe/commit, class specific
  descriptors, BOS), bulk IN delivery of the newest frame, status endpoint.
* `camera.rs` - Camera2/NDK bridge: opens the camera on demand, streams into an
  `AImageReader` (HAL JPEG when available, YUV otherwise), strips the EXIF
  payload, keeps only the newest frame and releases the camera as soon as the
  guest stops streaming. Camera selection and frame-rate cap can be overridden
  with `/data/local/tmp/droidvm-uvc-camera` and `.../droidvm-uvc-fps`.
* `jpeg.rs` - software MJPEG encoder (YUV420 -> baseline JPEG) used when the HAL
  JPEG path is unavailable, plus the EXIF stripping helper.
* `mediacodec.rs` - optional MediaCodec JPEG encoder attempt (this device has no
  hardware JPEG encoder, so it falls back to the HAL path).

### VPU passthrough (`src/crosvm/cmdline.rs`)
* `cfg.v4l2_proxy` already exists in crosvm (virtio-media V4L2 passthrough).
  This fork additionally reads `/data/local/tmp/droidvm-vpu` and appends the
  path listed there, so the app can expose a hardware codec node
  (`/dev/video32`, Qualcomm msm_vidc) to the guest without changing its crosvm
  command line. Empty/absent file keeps the old behaviour.

### aarch64 (`aarch64/src/lib.rs`)
* TPM TIS window placed at 0x7000 (`AARCH64_TIS_TPM_ADDR`) so it matches the
  Oct-18 firmware; the CPPC mailbox device was removed because its 0x8000 page
  collides with the TIS window.

## edk2 GunyahPkg

* `Drivers/DroidVMTpmAcpiDxe` - reads the `google,goldfish-tpm` device tree node,
  installs an SSDT with `_HID/_CID = "MSFT0101"`, the TIS `_CRS` window and the
  PPI `_DSM` methods, and publishes a TPM 2.0 ACPI table (revision 4,
  StartMethod = TIS).
* `Drivers/GunyahSecureBootVars` - publishes `SecureBoot`/`SetupMode` from the
  `droidvm,secureboot` device tree node and appends the db authority
  measurement into PCR7 (EV_EFI_VARIABLE_AUTHORITY). Both variables are written
  as non-volatile so they exist before `Tcg2Dxe` measures PCR7, and the driver
  is ordered before `Tcg2Dxe` in the FV for the same reason.
* `GunyahKernel.dsc` / `GunyahFvMain.fdf.inc` - TCG2 stack (Tcg2Dxe,
  Tpm2DeviceLibDTpm, DxeTcg2PhysicalPresenceLib, HashLibTpm2), TPM base address
  PCD, battery driver and the Secure Boot variable driver.
