# 双 UVC 摄像头改动说明

一个 VM 里可以出现两台模拟 USB 摄像头（UVC 1.1 / MJPEG），彼此独立：各自一个采集线程、
各自一个 host camera（后置 0 / 前置 1），Windows 免驱识别为两台 USB Video Device。

## crosvm

* `devices/src/usb/backend/uvc_backend/camera.rs`
  * `CAMERA_SLOTS = 2`；`LATEST_FRAME` / `FRAME_SEQ` / `STREAM_WANTED` / `LAST_ACTIVITY`
    由单例改为按槽位的数组；
  * `take_latest_frame` / `store_frame` / `clear_frame` / `set_streaming` /
    `touch_activity` / `streaming_wanted` 增加 `camera_slot`；
  * `start_capture(slot, requested)` / `spawn_camera(slot, requested)` /
    `stream_once(slot, …)`；线程名 `uvc-camera-N`，首帧转储 `frame1-N.jpg`；
  * 摄像头选择：`""` 按槽位取第 N 台，`back`/`front`，字面 id，纯数字下标。
* `devices/src/usb/backend/uvc_backend/uvc_device.rs`
  * `UvcDevice` 增加 `camera_slot`；`new()` / `attach_virtual_camera()` 接收 slot 与 camera id；
  * `handle_control` / `handle_class_request` / `handle_bulk_in` 传入 slot（三者都是无 `self`
    的关联函数）。
* `devices/src/usb/backend/uvc_backend/descriptors.rs`
  * `pub const fn device_descriptor(slot) -> [u8; 18]`，`bcdDevice = 1.<slot>`，两台设备描述符不同。
* `devices/src/usb/backend/device_provider.rs`
  * `attach_virtual_camera()` 按列表逐台创建；
  * `uvc_camera_index_list()` 取值顺序：`--uvc-camera`（`set_uvc_cameras` 写入的 `OnceLock`）
    → `/data/local/tmp/droidvm-uvc-cameras`（每行一个）→ 默认 `["0"]`。
* `src/crosvm/cmdline.rs`
  * 新增 `--uvc-camera <ID>`（可重复），在原有 media 配置块里交给 `device_provider`。

## app

* `PeripheralType.VIRTIO_CAMERA` 由不可用改为可用，类型名改为「USB 摄像头（UVC）」，
  红字「功能待实现」随之消失（`tv_peripheral_unavailable` 由 `isAvailable()` 控制）。
* `CrosvmBackendInstance.buildPeripheralCommand()` 每个摄像头外设输出一条
  `--uvc-camera <id>`；未指定主机摄像头时传该行序号（0、1…），
  所以两个默认行会落到两台不同摄像头上。
* 字符串：en `USB camera (UVC)`、zh-rCN `USB 摄像头（UVC）`、zh-rTW `USB 攝影機（UVC）`。

## 已验证

* 两台摄像头各自打开成功：`camera 0 → "0"`、`camera 1 → "1"`（`/data/local/tmp/camprobe.log`）。
* 手工回退方式（不经 app）：`printf '0\n1\n' > /data/local/tmp/droidvm-uvc-cameras`。
