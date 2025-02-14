#include <errno.h>
#include <fcntl.h>
#include <linux/cdrom.h>
#include <linux/fs.h>
#include <linux/input.h>
#include <linux/kd.h>
#include <linux/kvm.h>
#include <linux/nvme_ioctl.h>
#include <linux/sockios.h>
#include <linux/usb/cdc-wdm.h>
#include <linux/vt.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <scsi/sg.h>
#include <sys/ioctl.h>
#include <asm/vmx.h>

#include <bits/ensure.h>
#include <bits/errors.hpp>
#include <bragi/helpers-frigg.hpp>
#include <frg/vector.hpp>
#include <mlibc/all-sysdeps.hpp>
#include <mlibc/allocator.hpp>
#include <mlibc/debug.hpp>
#include <mlibc/posix-pipe.hpp>

#include <fs.frigg_bragi.hpp>
#include <posix.frigg_bragi.hpp>

namespace mlibc {

static constexpr bool logIoctls = false;

int ioctl_drm(int fd, unsigned long request, void *arg, int *result, HelHandle handle);

int sys_ioctl(int fd, unsigned long request, void *arg, int *result) {
	if (logIoctls)
		mlibc::infoLogger() << "mlibc: ioctl with"
		                    << " type: 0x" << frg::hex_fmt(_IOC_TYPE(request)) << ", number: 0x"
		                    << frg::hex_fmt(_IOC_NR(request))
		                    << " (raw request: " << frg::hex_fmt(request) << ")"
		                    << " on fd " << fd << frg::endlog;

	SignalGuard sguard;
	auto handle = getHandleForFd(fd);
	if (!handle)
		return EBADF;

	if (_IOC_TYPE(request) == 'd') {
		return ioctl_drm(fd, request, arg, result, handle);
	}

	auto handle_siocgif =
	    [&arg, &request, &result](
	        void (*req_setup)(managarm::fs::IfreqRequest<MemoryAllocator> &req, struct ifreq *ifr),
	        int (*resp_parse)(managarm::fs::IfreqReply<MemoryAllocator> &resp, struct ifreq *ifr)
	    ) -> int {
		if (!arg)
			return EFAULT;

		auto ifr = reinterpret_cast<struct ifreq *>(arg);

		managarm::posix::NetserverRequest<MemoryAllocator> token_req(getSysdepsAllocator());
		managarm::fs::IfreqRequest<MemoryAllocator> req(getSysdepsAllocator());
		req.set_command(request);

		req_setup(req, ifr);

		auto [offer, send_token_req, send_req, send_req_tail, recv_resp] = exchangeMsgsSync(
		    getPosixLane(),
		    helix_ng::offer(
		        helix_ng::want_lane,
		        helix_ng::sendBragiHeadOnly(token_req, getSysdepsAllocator()),
		        helix_ng::sendBragiHeadTail(req, getSysdepsAllocator()),
		        helix_ng::recvInline()
		    )
		);

		HEL_CHECK(offer.error());
		HEL_CHECK(send_token_req.error());
		HEL_CHECK(send_req.error());
		HEL_CHECK(send_req_tail.error());
		HEL_CHECK(recv_resp.error());

		auto preamble = bragi::read_preamble(recv_resp);

		frg::vector<uint8_t, MemoryAllocator> tailBuffer{getSysdepsAllocator()};
		tailBuffer.resize(preamble.tail_size());
		auto [recv_tail] = exchangeMsgsSync(
		    offer.descriptor().getHandle(),
		    helix_ng::recvBuffer(tailBuffer.data(), tailBuffer.size())
		);

		HEL_CHECK(recv_tail.error());

		auto resp = *bragi::parse_head_tail<managarm::fs::IfreqReply>(
		    recv_resp, tailBuffer, getSysdepsAllocator()
		);
		recv_resp.reset();

		int ret = resp_parse(resp, ifr);

		if (result)
			*result = 0;
		return ret;
	};

	managarm::fs::IoctlRequest<MemoryAllocator> ioctl_req(getSysdepsAllocator());

	switch (request) {
		case FIONBIO: {
			auto mode = reinterpret_cast<int *>(arg);
			int flags = fcntl(fd, F_GETFL, 0);
			if (*mode) {
				fcntl(fd, F_SETFL, flags | O_NONBLOCK);
			} else {
				fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
			}
			return 0;
		}
		case FIONREAD: {
			auto argp = reinterpret_cast<int *>(arg);

			auto handle = getHandleForFd(fd);
			if (!handle)
				return EBADF;

			if (!argp)
				return EINVAL;

			managarm::fs::GenericIoctlRequest<MemoryAllocator> req(getSysdepsAllocator());
			req.set_command(FIONREAD);

			auto [offer, send_ioctl_req, send_req, recv_resp] = exchangeMsgsSync(
			    handle,
			    helix_ng::offer(
			        helix_ng::sendBragiHeadOnly(ioctl_req, getSysdepsAllocator()),
			        helix_ng::sendBragiHeadOnly(req, getSysdepsAllocator()),
			        helix_ng::recvInline()
			    )
			);

			HEL_CHECK(offer.error());
			HEL_CHECK(send_ioctl_req.error());
			HEL_CHECK(send_req.error());
			HEL_CHECK(recv_resp.error());

			managarm::fs::GenericIoctlReply<MemoryAllocator> resp(getSysdepsAllocator());
			resp.ParseFromArray(recv_resp.data(), recv_resp.length());
			if (resp.error() == managarm::fs::Errors::NOT_CONNECTED) {
				return ENOTCONN;
			} else {
				__ensure(resp.error() == managarm::fs::Errors::SUCCESS);

				*argp = resp.fionread_count();

				return 0;
			}
		}
		case FIOCLEX: {
			managarm::posix::IoctlFioclexRequest<MemoryAllocator> req(getSysdepsAllocator());
			req.set_fd(fd);

			auto [offer, sendReq, recvResp] = exchangeMsgsSync(
			    getPosixLane(),
			    helix_ng::offer(
			        helix_ng::sendBragiHeadOnly(req, getSysdepsAllocator()), helix_ng::recvInline()
			    )
			);

			HEL_CHECK(offer.error());
			HEL_CHECK(sendReq.error());
			if (recvResp.error() == kHelErrDismissed)
				return EINVAL;
			HEL_CHECK(recvResp.error());

			managarm::posix::SvrResponse<MemoryAllocator> resp(getSysdepsAllocator());
			resp.ParseFromArray(recvResp.data(), recvResp.length());
			__ensure(resp.error() == managarm::posix::Errors::SUCCESS);
			return 0;
		}
		case TCGETS: {
			auto param = reinterpret_cast<struct termios *>(arg);

			managarm::fs::GenericIoctlRequest<MemoryAllocator> req(getSysdepsAllocator());
			req.set_command(request);

			auto [offer, send_ioctl_req, send_req, recv_resp, recv_attrs] = exchangeMsgsSync(
			    handle,
			    helix_ng::offer(
			        helix_ng::sendBragiHeadOnly(ioctl_req, getSysdepsAllocator()),
			        helix_ng::sendBragiHeadOnly(req, getSysdepsAllocator()),
			        helix_ng::recvInline(),
			        helix_ng::recvBuffer(param, sizeof(struct termios))
			    )
			);

			HEL_CHECK(offer.error());
			HEL_CHECK(send_ioctl_req.error());
			if (send_req.error() == kHelErrDismissed)
				return EINVAL;
			HEL_CHECK(send_req.error());
			HEL_CHECK(recv_resp.error());
			HEL_CHECK(recv_attrs.error());

			managarm::fs::GenericIoctlReply<MemoryAllocator> resp(getSysdepsAllocator());
			resp.ParseFromArray(recv_resp.data(), recv_resp.length());
			__ensure(resp.error() == managarm::fs::Errors::SUCCESS);
			__ensure(recv_attrs.actualLength() == sizeof(struct termios));
			*result = resp.result();
			return 0;
		}
		case TCSETS: {
			auto param = reinterpret_cast<struct termios *>(arg);

			managarm::fs::GenericIoctlRequest<MemoryAllocator> req(getSysdepsAllocator());
			req.set_command(request);

			auto [offer, send_ioctl_req, send_req, send_attrs, recv_resp] = exchangeMsgsSync(
			    handle,
			    helix_ng::offer(
			        helix_ng::sendBragiHeadOnly(ioctl_req, getSysdepsAllocator()),
			        helix_ng::sendBragiHeadOnly(req, getSysdepsAllocator()),
			        helix_ng::sendBuffer(param, sizeof(struct termios)),
			        helix_ng::recvInline()
			    )
			);

			HEL_CHECK(offer.error());
			HEL_CHECK(send_ioctl_req.error());
			if (send_req.error() == kHelErrDismissed)
				return EINVAL;
			HEL_CHECK(send_req.error());
			HEL_CHECK(send_attrs.error());
			HEL_CHECK(recv_resp.error());

			managarm::fs::GenericIoctlReply<MemoryAllocator> resp(getSysdepsAllocator());
			resp.ParseFromArray(recv_resp.data(), recv_resp.length());
			__ensure(resp.error() == managarm::fs::Errors::SUCCESS);
			if (result)
				*result = resp.result();
			return 0;
		}
		case TIOCSCTTY: {
			managarm::fs::GenericIoctlRequest<MemoryAllocator> req(getSysdepsAllocator());
			req.set_command(request);

			auto [offer, send_ioctl_req, send_req, imbue_creds, recv_resp] = exchangeMsgsSync(
			    handle,
			    helix_ng::offer(
			        helix_ng::sendBragiHeadOnly(ioctl_req, getSysdepsAllocator()),
			        helix_ng::sendBragiHeadOnly(req, getSysdepsAllocator()),
			        helix_ng::imbueCredentials(),
			        helix_ng::recvInline()
			    )
			);

			HEL_CHECK(offer.error());
			if (send_req.error() == kHelErrDismissed)
				return EINVAL;
			HEL_CHECK(send_ioctl_req.error());
			HEL_CHECK(imbue_creds.error());
			HEL_CHECK(send_req.error());
			HEL_CHECK(recv_resp.error());

			managarm::fs::GenericIoctlReply<MemoryAllocator> resp(getSysdepsAllocator());
			resp.ParseFromArray(recv_resp.data(), recv_resp.length());

			if (resp.error() == managarm::fs::Errors::ILLEGAL_ARGUMENT) {
				return EINVAL;
			} else if (resp.error() == managarm::fs::Errors::INSUFFICIENT_PERMISSIONS) {
				return EPERM;
			}
			__ensure(resp.error() == managarm::fs::Errors::SUCCESS);
			*result = resp.result();
			return 0;
		}
		case TIOCGWINSZ: {
			auto param = reinterpret_cast<struct winsize *>(arg);

			managarm::fs::GenericIoctlRequest<MemoryAllocator> req(getSysdepsAllocator());
			req.set_command(request);

			auto [offer, send_ioctl_req, send_req, recv_resp] = exchangeMsgsSync(
			    handle,
			    helix_ng::offer(
			        helix_ng::sendBragiHeadOnly(ioctl_req, getSysdepsAllocator()),
			        helix_ng::sendBragiHeadOnly(req, getSysdepsAllocator()),
			        helix_ng::recvInline()
			    )
			);

			HEL_CHECK(offer.error());
			HEL_CHECK(send_ioctl_req.error());
			if (send_req.error() == kHelErrDismissed)
				return EINVAL;
			HEL_CHECK(send_req.error());
			if (recv_resp.error() == kHelErrDismissed)
				return EINVAL;
			HEL_CHECK(recv_resp.error());

			managarm::fs::GenericIoctlReply<MemoryAllocator> resp(getSysdepsAllocator());
			resp.ParseFromArray(recv_resp.data(), recv_resp.length());
			if (resp.error() == managarm::fs::Errors::ILLEGAL_OPERATION_TARGET)
				return EINVAL;
			__ensure(resp.error() == managarm::fs::Errors::SUCCESS);

			*result = resp.result();
			param->ws_col = resp.pts_width();
			param->ws_row = resp.pts_height();
			param->ws_xpixel = resp.pts_pixel_width();
			param->ws_ypixel = resp.pts_pixel_height();
			return 0;
		}
		case TIOCSWINSZ: {
			auto param = reinterpret_cast<const struct winsize *>(arg);

			managarm::fs::GenericIoctlRequest<MemoryAllocator> req(getSysdepsAllocator());
			req.set_command(request);
			req.set_pts_width(param->ws_col);
			req.set_pts_height(param->ws_row);
			req.set_pts_pixel_width(param->ws_xpixel);
			req.set_pts_pixel_height(param->ws_ypixel);

			auto [offer, send_ioctl_req, send_req, recv_resp] = exchangeMsgsSync(
			    handle,
			    helix_ng::offer(
			        helix_ng::sendBragiHeadOnly(ioctl_req, getSysdepsAllocator()),
			        helix_ng::sendBragiHeadOnly(req, getSysdepsAllocator()),
			        helix_ng::recvInline()
			    )
			);
			HEL_CHECK(offer.error());
			HEL_CHECK(send_ioctl_req.error());
			if (send_req.error() == kHelErrDismissed)
				return EINVAL;
			HEL_CHECK(send_req.error());
			HEL_CHECK(recv_resp.error());

			managarm::fs::GenericIoctlReply<MemoryAllocator> resp(getSysdepsAllocator());
			resp.ParseFromArray(recv_resp.data(), recv_resp.length());
			__ensure(resp.error() == managarm::fs::Errors::SUCCESS);

			*result = resp.result();
			return 0;
		}
		case TIOCGPTN: {
			auto param = reinterpret_cast<int *>(arg);

			managarm::fs::GenericIoctlRequest<MemoryAllocator> req(getSysdepsAllocator());
			req.set_command(request);

			auto [offer, send_ioctl_req, send_req, recv_resp] = exchangeMsgsSync(
			    handle,
			    helix_ng::offer(
			        helix_ng::sendBragiHeadOnly(ioctl_req, getSysdepsAllocator()),
			        helix_ng::sendBragiHeadOnly(req, getSysdepsAllocator()),
			        helix_ng::recvInline()
			    )
			);
			HEL_CHECK(offer.error());
			HEL_CHECK(send_ioctl_req.error());
			if (send_req.error() == kHelErrDismissed)
				return EINVAL;
			HEL_CHECK(send_req.error());
			HEL_CHECK(recv_resp.error());

			managarm::fs::GenericIoctlReply<MemoryAllocator> resp(getSysdepsAllocator());
			resp.ParseFromArray(recv_resp.data(), recv_resp.length());
			__ensure(resp.error() == managarm::fs::Errors::SUCCESS);
			*param = resp.pts_index();
			if (result)
				*result = resp.result();
			return 0;
		}
		case TIOCGPGRP: {
			managarm::fs::GenericIoctlRequest<MemoryAllocator> req(getSysdepsAllocator());
			req.set_command(request);

			frg::string<MemoryAllocator> ser(getSysdepsAllocator());
			req.SerializeToString(&ser);

			auto [offer, send_ioctl_req, send_req, imbue_creds, recv_resp] = exchangeMsgsSync(
			    handle,
			    helix_ng::offer(
			        helix_ng::sendBragiHeadOnly(ioctl_req, getSysdepsAllocator()),
			        helix_ng::sendBuffer(ser.data(), ser.size()),
			        helix_ng::imbueCredentials(),
			        helix_ng::recvInline()
			    )
			);

			HEL_CHECK(offer.error());
			HEL_CHECK(send_ioctl_req.error());
			if (send_req.error())
				return EINVAL;
			HEL_CHECK(send_req.error());
			if (imbue_creds.error()) {
				infoLogger(
				) << "mlibc: TIOCGPGRP used on unexpected socket, returning EINVAL (FIXME)"
				  << frg::endlog;
				return EINVAL;
			}
			HEL_CHECK(imbue_creds.error());
			HEL_CHECK(recv_resp.error());

			managarm::fs::GenericIoctlReply<MemoryAllocator> resp(getSysdepsAllocator());
			resp.ParseFromArray(recv_resp.data(), recv_resp.length());
			if (resp.error() == managarm::fs::Errors::NOT_A_TERMINAL) {
				return ENOTTY;
			}
			__ensure(resp.error() == managarm::fs::Errors::SUCCESS);
			*result = resp.result();
			*static_cast<int *>(arg) = resp.pid();
			return 0;
		}
		case TIOCSPGRP: {
			auto param = reinterpret_cast<int *>(arg);

			managarm::fs::GenericIoctlRequest<MemoryAllocator> req(getSysdepsAllocator());
			req.set_command(request);
			req.set_pgid(*param);

			frg::string<MemoryAllocator> ser(getSysdepsAllocator());
			req.SerializeToString(&ser);

			auto [offer, send_ioctl_req, send_req, imbue_creds, recv_resp] = exchangeMsgsSync(
			    handle,
			    helix_ng::offer(
			        helix_ng::sendBragiHeadOnly(ioctl_req, getSysdepsAllocator()),
			        helix_ng::sendBuffer(ser.data(), ser.size()),
			        helix_ng::imbueCredentials(),
			        helix_ng::recvInline()
			    )
			);

			HEL_CHECK(offer.error());
			HEL_CHECK(send_ioctl_req.error());
			if (send_req.error() == kHelErrDismissed)
				return EINVAL;
			HEL_CHECK(send_req.error());
			HEL_CHECK(imbue_creds.error());
			HEL_CHECK(recv_resp.error());

			managarm::fs::GenericIoctlReply<MemoryAllocator> resp(getSysdepsAllocator());
			resp.ParseFromArray(recv_resp.data(), recv_resp.length());
			if (resp.error() == managarm::fs::Errors::INSUFFICIENT_PERMISSIONS) {
				return EPERM;
			} else if (resp.error() == managarm::fs::Errors::ILLEGAL_ARGUMENT) {
				return EINVAL;
			}
			__ensure(resp.error() == managarm::fs::Errors::SUCCESS);
			*result = resp.result();
			return 0;
		}
		case TIOCGSID: {
			managarm::fs::GenericIoctlRequest<MemoryAllocator> req(getSysdepsAllocator());
			req.set_command(request);

			frg::string<MemoryAllocator> ser(getSysdepsAllocator());
			req.SerializeToString(&ser);

			auto [offer, send_ioctl_req, send_req, imbue_creds, recv_resp] = exchangeMsgsSync(
			    handle,
			    helix_ng::offer(
			        helix_ng::sendBragiHeadOnly(ioctl_req, getSysdepsAllocator()),
			        helix_ng::sendBuffer(ser.data(), ser.size()),
			        helix_ng::imbueCredentials(),
			        helix_ng::recvInline()
			    )
			);

			HEL_CHECK(offer.error());
			if (send_ioctl_req.error())
				return EINVAL;
			HEL_CHECK(send_ioctl_req.error());
			if (send_req.error())
				return EINVAL;
			HEL_CHECK(send_req.error());
			if (imbue_creds.error() == kHelErrDismissed)
				return EINVAL;
			HEL_CHECK(imbue_creds.error());
			HEL_CHECK(recv_resp.error());

			managarm::fs::GenericIoctlReply<MemoryAllocator> resp(getSysdepsAllocator());
			resp.ParseFromArray(recv_resp.data(), recv_resp.length());
			if (resp.error() == managarm::fs::Errors::NOT_A_TERMINAL) {
				return ENOTTY;
			}
			__ensure(resp.error() == managarm::fs::Errors::SUCCESS);
			*result = resp.result();
			*static_cast<int *>(arg) = resp.pid();
			return 0;
		}
		case CDROM_GET_CAPABILITY: {
			managarm::fs::GenericIoctlRequest<MemoryAllocator> req(getSysdepsAllocator());
			req.set_command(request);

			frg::string<MemoryAllocator> ser(getSysdepsAllocator());
			req.SerializeToString(&ser);

			auto [offer, send_ioctl_req, send_req, recv_resp] = exchangeMsgsSync(
			    handle,
			    helix_ng::offer(
			        helix_ng::sendBragiHeadOnly(ioctl_req, getSysdepsAllocator()),
			        helix_ng::sendBuffer(ser.data(), ser.size()),
			        helix_ng::recvInline()
			    )
			);

			HEL_CHECK(offer.error());
			if (send_ioctl_req.error())
				return EINVAL;
			HEL_CHECK(send_ioctl_req.error());
			if (send_req.error())
				return EINVAL;
			HEL_CHECK(send_req.error());
			HEL_CHECK(recv_resp.error());

			managarm::fs::GenericIoctlReply<MemoryAllocator> resp(getSysdepsAllocator());
			resp.ParseFromArray(recv_resp.data(), recv_resp.length());
			if (resp.error() == managarm::fs::Errors::NOT_A_TERMINAL) {
				return ENOTTY;
			}
			__ensure(resp.error() == managarm::fs::Errors::SUCCESS);
			*result = resp.result();
			return 0;
		}
		case SIOCETHTOOL:
			mlibc::infoLogger() << "\e[35mmlibc: SIOCETHTOOL is a stub" << frg::endlog;
			*result = 0;
			return ENOSYS;
		case SIOCGSKNS:
			mlibc::infoLogger() << "\e[35mmlibc: SIOCGSKNS is a stub" << frg::endlog;
			*result = 0;
			return ENOSYS;
		case SG_IO:
			mlibc::infoLogger() << "\e[35mmlibc: SG_IO is a stub" << frg::endlog;
			*result = 0;
			return ENOSYS;
	} // end of switch()

	if (_IOC_TYPE(request) == 'E' && _IOC_NR(request) == _IOC_NR(EVIOCGVERSION)) {
		*reinterpret_cast<int *>(arg) = EV_VERSION;
		*result = 0;
		return 0;
	} else if (_IOC_TYPE(request) == 'E' && _IOC_NR(request) == _IOC_NR(EVIOCGID)) {
		memset(arg, 0, sizeof(struct input_id));
		auto param = reinterpret_cast<struct input_id *>(arg);

		managarm::fs::EvioGetIdRequest<MemoryAllocator> req(getSysdepsAllocator());

		auto [offer, send_ioctl_req, send_req, recv_resp] = exchangeMsgsSync(
		    handle,
		    helix_ng::offer(
		        helix_ng::want_lane,
		        helix_ng::sendBragiHeadOnly(ioctl_req, getSysdepsAllocator()),
		        helix_ng::sendBragiHeadOnly(req, getSysdepsAllocator()),
		        helix_ng::recvInline()
		    )
		);
		HEL_CHECK(offer.error());
		auto conversation = offer.descriptor();
		HEL_CHECK(send_ioctl_req.error());
		HEL_CHECK(send_req.error());
		HEL_CHECK(recv_resp.error());

		auto resp =
		    *bragi::parse_head_only<managarm::fs::EvioGetIdReply>(recv_resp, getSysdepsAllocator());
		recv_resp.reset();
		__ensure(resp.error() == managarm::fs::Errors::SUCCESS);

		param->bustype = resp.bustype();
		param->vendor = resp.vendor();
		param->product = resp.product();
		param->version = resp.version();

		*result = 0;
		return 0;
	} else if (_IOC_TYPE(request) == 'E' && _IOC_NR(request) == _IOC_NR(EVIOCGNAME(0))) {
		managarm::fs::EvioGetNameRequest<MemoryAllocator> req(getSysdepsAllocator());

		auto [offer, send_ioctl_req, send_req, recv_resp] = exchangeMsgsSync(
		    handle,
		    helix_ng::offer(
		        helix_ng::want_lane,
		        helix_ng::sendBragiHeadOnly(ioctl_req, getSysdepsAllocator()),
		        helix_ng::sendBragiHeadOnly(req, getSysdepsAllocator()),
		        helix_ng::recvInline()
		    )
		);
		HEL_CHECK(offer.error());
		auto conversation = offer.descriptor();
		HEL_CHECK(send_ioctl_req.error());
		HEL_CHECK(send_req.error());
		HEL_CHECK(recv_resp.error());

		auto preamble = bragi::read_preamble(recv_resp);
		__ensure(!preamble.error());

		frg::vector<uint8_t, MemoryAllocator> tailBuffer{getSysdepsAllocator()};
		tailBuffer.resize(preamble.tail_size());
		auto [recv_tail] = exchangeMsgsSync(
		    conversation.getHandle(), helix_ng::recvBuffer(tailBuffer.data(), tailBuffer.size())
		);

		HEL_CHECK(recv_tail.error());

		auto resp = *bragi::parse_head_tail<managarm::fs::EvioGetNameReply>(
		    recv_resp, tailBuffer, getSysdepsAllocator()
		);
		recv_resp.reset();
		__ensure(resp.error() == managarm::fs::Errors::SUCCESS);

		auto chunk = frg::min(_IOC_SIZE(request), resp.name().size() + 1);
		memcpy(arg, resp.name().data(), chunk);
		*result = chunk;
		return 0;
	} else if (_IOC_TYPE(request) == 'E' && _IOC_NR(request) == _IOC_NR(EVIOCGRAB)) {
		mlibc::infoLogger() << "mlibc: EVIOCGRAB is a no-op" << frg::endlog;
		*result = 0;
		return 0;
	} else if (_IOC_TYPE(request) == 'E' && _IOC_NR(request) == _IOC_NR(EVIOCGPHYS(0))) {
		// Returns the sysfs path of the device.
		const char *s = "input0";
		auto chunk = frg::min(_IOC_SIZE(request), strlen(s) + 1);
		memcpy(arg, s, chunk);
		*result = chunk;
		return 0;
	} else if (_IOC_TYPE(request) == 'E' && _IOC_NR(request) == _IOC_NR(EVIOCGUNIQ(0))) {
		// Returns a unique ID for the device.
		const char *s = "0";
		auto chunk = frg::min(_IOC_SIZE(request), strlen(s) + 1);
		memcpy(arg, s, chunk);
		*result = chunk;
		return 0;
	} else if (_IOC_TYPE(request) == 'E' && _IOC_NR(request) == _IOC_NR(EVIOCGPROP(0))) {
		// Returns a bitmask of properties of the device.
		auto size = _IOC_SIZE(request);
		memset(arg, 0, size);
		*result = size;
		return 0;
	} else if (_IOC_TYPE(request) == 'E' && _IOC_NR(request) == _IOC_NR(EVIOCGKEY(0))) {
		// Returns the current key state.
		auto size = _IOC_SIZE(request);
		memset(arg, 0, size);
		*result = size;
		return 0;
	} else if (_IOC_TYPE(request) == 'E' && _IOC_NR(request) == _IOC_NR(EVIOCGMTSLOTS(0))) {
		// this ioctl is completely, utterly undocumented
		// the _IOC_SIZE is a buffer size in bytes, which should be a multiple of int32_t
		// bytes should be at least sizeof(int32_t) large.
		// the argument (the pointer to the buffer) is an array of int32_t
		// the first entry is the number of values supplied, followed by the values
		// this would have been worthwhile to document ffs

		// the length argument is the buffer size, in bytes
		auto bytes = _IOC_SIZE(request);
		// the length argument should be a multiple of int32_t
		if (!bytes || bytes % sizeof(int32_t))
			return EINVAL;

		// the number of entries the buffer can hold
		auto entries = (bytes / sizeof(int32_t)) - 1;

		managarm::fs::EvioGetMultitouchSlotsRequest<MemoryAllocator> req(getSysdepsAllocator());
		req.set_code(*reinterpret_cast<uint32_t *>(arg));

		auto [offer, send_ioctl_req, send_req, recv_resp] = exchangeMsgsSync(
		    handle,
		    helix_ng::offer(
		        helix_ng::want_lane,
		        helix_ng::sendBragiHeadOnly(ioctl_req, getSysdepsAllocator()),
		        helix_ng::sendBragiHeadOnly(req, getSysdepsAllocator()),
		        helix_ng::recvInline()
		    )
		);
		HEL_CHECK(offer.error());
		auto conversation = offer.descriptor();
		HEL_CHECK(send_ioctl_req.error());
		HEL_CHECK(send_req.error());
		HEL_CHECK(recv_resp.error());

		auto preamble = bragi::read_preamble(recv_resp);
		__ensure(!preamble.error());

		frg::vector<uint8_t, MemoryAllocator> tailBuffer{getSysdepsAllocator()};
		tailBuffer.resize(preamble.tail_size());
		auto [recv_tail] = exchangeMsgsSync(
		    conversation.getHandle(), helix_ng::recvBuffer(tailBuffer.data(), tailBuffer.size())
		);

		HEL_CHECK(recv_tail.error());

		auto resp = *bragi::parse_head_tail<managarm::fs::EvioGetMultitouchSlotsReply>(
		    recv_resp, tailBuffer, getSysdepsAllocator()
		);
		recv_resp.reset();
		__ensure(resp.error() == managarm::fs::Errors::SUCCESS);

		auto param = reinterpret_cast<int32_t *>(arg);

		for (size_t i = 0; i < resp.values_size() && i < entries; i++) {
			param[i + 1] = resp.values(i);
		}

		param[0] = resp.values_size();

		return 0;
	} else if (_IOC_TYPE(request) == 'E' && _IOC_NR(request) == _IOC_NR(EVIOCGLED(0))) {
		// Returns the current LED state.
		auto size = _IOC_SIZE(request);
		memset(arg, 0, size);
		*result = size;
		return 0;
	} else if (_IOC_TYPE(request) == 'E' && _IOC_NR(request) == _IOC_NR(EVIOCGSW(0))) {
		auto size = _IOC_SIZE(request);
		memset(arg, 0, size);
		*result = size;
		return 0;
	} else if (_IOC_TYPE(request) == 'E' && _IOC_NR(request) >= _IOC_NR(EVIOCGBIT(0, 0))
	           && _IOC_NR(request) <= _IOC_NR(EVIOCGBIT(EV_MAX, 0))) {
		// Returns a bitmask of capabilities of the device.
		// If type is zero, return a mask of supported types.
		// As EV_SYN is zero, this implies that it is impossible
		// to get the mask of supported synthetic events.
		auto type = _IOC_NR(request) - _IOC_NR(EVIOCGBIT(0, 0));
		if (!type) {
			// TODO: Check with the Linux ABI if we have to do this.
			memset(arg, 0, _IOC_SIZE(request));

			managarm::fs::GenericIoctlRequest<MemoryAllocator> req(getSysdepsAllocator());
			req.set_command(EVIOCGBIT(0, 0));
			req.set_size(_IOC_SIZE(request));

			auto [offer, send_ioctl_req, send_req, recv_resp, recv_data] = exchangeMsgsSync(
			    handle,
			    helix_ng::offer(
			        helix_ng::sendBragiHeadOnly(ioctl_req, getSysdepsAllocator()),
			        helix_ng::sendBragiHeadOnly(req, getSysdepsAllocator()),
			        helix_ng::recvInline(),
			        helix_ng::recvBuffer(arg, _IOC_SIZE(request))
			    )
			);

			HEL_CHECK(offer.error());
			HEL_CHECK(send_ioctl_req.error());
			if (send_req.error() == kHelErrDismissed)
				return EINVAL;
			HEL_CHECK(send_req.error());
			HEL_CHECK(recv_resp.error());
			HEL_CHECK(recv_data.error());

			managarm::fs::GenericIoctlReply<MemoryAllocator> resp(getSysdepsAllocator());
			resp.ParseFromArray(recv_resp.data(), recv_resp.length());
			__ensure(resp.error() == managarm::fs::Errors::SUCCESS);
			*result = recv_data.actualLength();
			return 0;
		} else {
			// TODO: Check with the Linux ABI if we have to do this.
			memset(arg, 0, _IOC_SIZE(request));

			managarm::fs::GenericIoctlRequest<MemoryAllocator> req(getSysdepsAllocator());
			req.set_command(EVIOCGBIT(1, 0));
			req.set_input_type(type);
			req.set_size(_IOC_SIZE(request));

			auto [offer, send_ioctl_req, send_req, recv_resp, recv_data] = exchangeMsgsSync(
			    handle,
			    helix_ng::offer(
			        helix_ng::sendBragiHeadOnly(ioctl_req, getSysdepsAllocator()),
			        helix_ng::sendBragiHeadOnly(req, getSysdepsAllocator()),
			        helix_ng::recvInline(),
			        helix_ng::recvBuffer(arg, _IOC_SIZE(request))
			    )
			);

			HEL_CHECK(offer.error());
			HEL_CHECK(send_ioctl_req.error());
			if (send_req.error() == kHelErrDismissed)
				return EINVAL;
			HEL_CHECK(send_req.error());
			HEL_CHECK(recv_resp.error());
			HEL_CHECK(recv_data.error());

			managarm::fs::GenericIoctlReply<MemoryAllocator> resp(getSysdepsAllocator());
			resp.ParseFromArray(recv_resp.data(), recv_resp.length());
			__ensure(resp.error() == managarm::fs::Errors::SUCCESS);
			*result = recv_data.actualLength();
			return 0;
		}
	} else if (_IOC_TYPE(request) == 'E' && _IOC_NR(request) == _IOC_NR(EVIOCSCLOCKID)) {
		auto param = reinterpret_cast<int *>(arg);

		managarm::fs::GenericIoctlRequest<MemoryAllocator> req(getSysdepsAllocator());
		req.set_command(request);
		req.set_input_clock(*param);

		auto [offer, send_ioctl_req, send_req, recv_resp] = exchangeMsgsSync(
		    handle,
		    helix_ng::offer(
		        helix_ng::sendBragiHeadOnly(ioctl_req, getSysdepsAllocator()),
		        helix_ng::sendBragiHeadOnly(req, getSysdepsAllocator()),
		        helix_ng::recvInline()
		    )
		);

		HEL_CHECK(offer.error());
		HEL_CHECK(send_ioctl_req.error());
		if (send_req.error() == kHelErrDismissed)
			return EINVAL;
		HEL_CHECK(send_req.error());
		HEL_CHECK(recv_resp.error());

		managarm::fs::GenericIoctlReply<MemoryAllocator> resp(getSysdepsAllocator());
		resp.ParseFromArray(recv_resp.data(), recv_resp.length());
		__ensure(resp.error() == managarm::fs::Errors::SUCCESS);
		*result = resp.result();
		return 0;
	} else if (_IOC_TYPE(request) == 'E' && _IOC_NR(request) >= _IOC_NR(EVIOCGABS(0))
	           && _IOC_NR(request) <= _IOC_NR(EVIOCGABS(ABS_MAX))) {
		auto param = reinterpret_cast<struct input_absinfo *>(arg);

		auto type = _IOC_NR(request) - _IOC_NR(EVIOCGABS(0));
		managarm::fs::GenericIoctlRequest<MemoryAllocator> req(getSysdepsAllocator());
		req.set_command(EVIOCGABS(0));
		req.set_input_type(type);

		auto [offer, send_ioctl_req, send_req, recv_resp] = exchangeMsgsSync(
		    handle,
		    helix_ng::offer(
		        helix_ng::sendBragiHeadOnly(ioctl_req, getSysdepsAllocator()),
		        helix_ng::sendBragiHeadOnly(req, getSysdepsAllocator()),
		        helix_ng::recvInline()
		    )
		);

		HEL_CHECK(offer.error());
		HEL_CHECK(send_ioctl_req.error());
		if (send_req.error() == kHelErrDismissed)
			return EINVAL;
		HEL_CHECK(send_req.error());
		HEL_CHECK(recv_resp.error());

		managarm::fs::GenericIoctlReply<MemoryAllocator> resp(getSysdepsAllocator());
		resp.ParseFromArray(recv_resp.data(), recv_resp.length());
		__ensure(resp.error() == managarm::fs::Errors::SUCCESS);

		param->value = resp.input_value();
		param->minimum = resp.input_min();
		param->maximum = resp.input_max();
		param->fuzz = resp.input_fuzz();
		param->flat = resp.input_flat();
		param->resolution = resp.input_resolution();

		*result = resp.result();
		return 0;
	} else if (request == KDSETMODE) {
		auto param = reinterpret_cast<unsigned int *>(arg);
		mlibc::infoLogger() << "\e[35mmlibc: KD_SETMODE(" << frg::hex_fmt(param) << ") is a no-op"
		                    << frg::endlog;

		*result = 0;
		return 0;
	} else if (request == KDGETMODE) {
		auto param = reinterpret_cast<unsigned int *>(arg);
		mlibc::infoLogger() << "\e[35mmlibc: KD_GETMODE is a no-op" << frg::endlog;
		*param = 0;

		*result = 0;
		return 0;
	} else if (request == KDSKBMODE) {
		auto param = reinterpret_cast<long>(arg);
		mlibc::infoLogger() << "\e[35mmlibc: KD_SKBMODE(" << frg::hex_fmt(param) << ") is a no-op"
		                    << frg::endlog;

		*result = 0;
		return 0;
	} else if (request == VT_SETMODE) {
		// auto param = reinterpret_cast<struct vt_mode *>(arg);
		mlibc::infoLogger() << "\e[35mmlibc: VT_SETMODE is a no-op" << frg::endlog;

		*result = 0;
		return 0;
	} else if (request == VT_GETSTATE) {
		auto param = reinterpret_cast<struct vt_stat *>(arg);

		param->v_active = 0;
		param->v_signal = 0;
		param->v_state = 0;

		mlibc::infoLogger() << "\e[35mmlibc: VT_GETSTATE is a no-op" << frg::endlog;

		*result = 0;
		return 0;
	} else if (request == VT_ACTIVATE || request == VT_WAITACTIVE) {
		mlibc::infoLogger() << "\e[35mmlibc: VT_ACTIVATE/VT_WAITACTIVE are no-ops" << frg::endlog;
		*result = 0;
		return 0;
	} else if (request == TIOCSPTLCK) {
		mlibc::infoLogger() << "\e[35mmlibc: TIOCSPTLCK is a no-op" << frg::endlog;
		if (result)
			*result = 0;
		return 0;
	} else if (request == SIOCGIFNAME) {
		return handle_siocgif(
		    [](auto req, auto ifr) { req.set_index(ifr->ifr_ifindex); },
		    [](auto resp, auto ifr) {
			    if (resp.error() != managarm::fs::Errors::SUCCESS)
				    return EINVAL;
			    strncpy(ifr->ifr_name, resp.name().data(), IFNAMSIZ);
			    return 0;
		    }
		);
	} else if (request == SIOCGIFCONF) {
		if (!arg)
			return EFAULT;

		auto ifc = reinterpret_cast<struct ifconf *>(arg);

		managarm::posix::NetserverRequest<MemoryAllocator> token_req(getSysdepsAllocator());
		managarm::fs::IfreqRequest<MemoryAllocator> req(getSysdepsAllocator());
		req.set_command(request);

		auto [offer, send_token_req, send_req, send_tail, recv_resp] = exchangeMsgsSync(
		    getPosixLane(),
		    helix_ng::offer(
		        helix_ng::want_lane,
		        helix_ng::sendBragiHeadOnly(token_req, getSysdepsAllocator()),
		        helix_ng::sendBragiHeadTail(req, getSysdepsAllocator()),
		        helix_ng::recvInline()
		    )
		);

		auto conversation = offer.descriptor();

		HEL_CHECK(offer.error());
		HEL_CHECK(send_token_req.error());
		HEL_CHECK(send_req.error());
		HEL_CHECK(send_tail.error());
		HEL_CHECK(recv_resp.error());

		auto preamble = bragi::read_preamble(recv_resp);
		__ensure(!preamble.error());

		frg::vector<uint8_t, MemoryAllocator> tailBuffer{getSysdepsAllocator()};
		tailBuffer.resize(preamble.tail_size());
		auto [recv_tail] = exchangeMsgsSync(
		    conversation.getHandle(), helix_ng::recvBuffer(tailBuffer.data(), tailBuffer.size())
		);

		HEL_CHECK(recv_tail.error());

		auto resp = *bragi::parse_head_tail<managarm::fs::IfconfReply>(
		    recv_resp, tailBuffer, getSysdepsAllocator()
		);
		recv_resp.reset();

		__ensure(resp.error() == managarm::fs::Errors::SUCCESS);

		if (ifc->ifc_buf == nullptr) {
			ifc->ifc_len = int(resp.ifconf_size() * sizeof(struct ifreq));
			return 0;
		}

		ifc->ifc_len = frg::min(int(resp.ifconf_size() * sizeof(struct ifreq)), ifc->ifc_len);

		for (size_t i = 0; i < frg::min(resp.ifconf_size(), ifc->ifc_len / sizeof(struct ifreq));
		     ++i) {
			auto &conf = resp.ifconf()[i];

			sockaddr_in addr{};
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = htonl(conf.ip4());

			ifreq *req = &ifc->ifc_req[i];
			strncpy(req->ifr_name, conf.name().data(), IFNAMSIZ);
			memcpy(&req->ifr_addr, &addr, sizeof(addr));
		}

		if (result)
			*result = 0;
		return 0;
	} else if (request == SIOCGIFNETMASK) {
		return handle_siocgif(
		    [](auto req, auto ifr) {
			    req.set_name(frg::string<MemoryAllocator>{ifr->ifr_name, getSysdepsAllocator()});
		    },
		    [](auto resp, auto ifr) {
			    if (resp.error() != managarm::fs::Errors::SUCCESS)
				    return EINVAL;

			    sockaddr_in addr{};
			    addr.sin_family = AF_INET;
			    addr.sin_addr = {htonl(resp.ip4_netmask())};
			    memcpy(&ifr->ifr_netmask, &addr, sizeof(addr));

			    return 0;
		    }
		);
	} else if (request == SIOCGIFINDEX) {
		return handle_siocgif(
		    [](auto req, auto ifr) {
			    req.set_name(frg::string<MemoryAllocator>{ifr->ifr_name, getSysdepsAllocator()});
		    },
		    [](auto resp, auto ifr) {
			    if (resp.error() != managarm::fs::Errors::SUCCESS)
				    return EINVAL;
			    ifr->ifr_ifindex = resp.index();
			    return 0;
		    }
		);
	} else if (request == SIOCGIFFLAGS) {
		return handle_siocgif(
		    [](auto req, auto ifr) {
			    req.set_name(frg::string<MemoryAllocator>{ifr->ifr_name, getSysdepsAllocator()});
		    },
		    [](auto resp, auto ifr) {
			    if (resp.error() != managarm::fs::Errors::SUCCESS)
				    return EINVAL;
			    ifr->ifr_flags = resp.flags();
			    return 0;
		    }
		);
	} else if (request == SIOCGIFADDR) {
		return handle_siocgif(
		    [](auto req, auto ifr) {
			    req.set_name(frg::string<MemoryAllocator>{ifr->ifr_name, getSysdepsAllocator()});
		    },
		    [](auto resp, auto ifr) {
			    if (resp.error() != managarm::fs::Errors::SUCCESS)
				    return EINVAL;

			    sockaddr_in addr{};
			    addr.sin_family = AF_INET;
			    addr.sin_addr = {htonl(resp.ip4_addr())};
			    memcpy(&ifr->ifr_addr, &addr, sizeof(addr));

			    return 0;
		    }
		);
	} else if (request == SIOCGIFMTU) {
		return handle_siocgif(
		    [](auto req, auto ifr) {
			    req.set_name(frg::string<MemoryAllocator>{ifr->ifr_name, getSysdepsAllocator()});
		    },
		    [](auto resp, auto ifr) {
			    if (resp.error() != managarm::fs::Errors::SUCCESS)
				    return EINVAL;

			    ifr->ifr_mtu = resp.mtu();

			    return 0;
		    }
		);
	} else if (request == SIOCGIFBRDADDR) {
		return handle_siocgif(
		    [](auto req, auto ifr) {
			    req.set_name(frg::string<MemoryAllocator>{ifr->ifr_name, getSysdepsAllocator()});
		    },
		    [](auto resp, auto ifr) {
			    if (resp.error() != managarm::fs::Errors::SUCCESS)
				    return EINVAL;

			    sockaddr_in addr{};
			    addr.sin_family = AF_INET;
			    addr.sin_addr = {htonl(resp.ip4_broadcast_addr())};
			    memcpy(&ifr->ifr_broadaddr, &addr, sizeof(addr));

			    return 0;
		    }
		);
	} else if (request == SIOCGIFHWADDR) {
		return handle_siocgif(
		    [](auto req, auto ifr) {
			    req.set_name(frg::string<MemoryAllocator>{ifr->ifr_name, getSysdepsAllocator()});
		    },
		    [](auto resp, auto ifr) {
			    if (resp.error() != managarm::fs::Errors::SUCCESS)
				    return EINVAL;

			    sockaddr addr{};
			    addr.sa_family = ARPHRD_ETHER;
			    memcpy(addr.sa_data, resp.mac().data(), 6);
			    memcpy(&ifr->ifr_hwaddr, &addr, sizeof(addr));

			    return 0;
		    }
		);
	} else if (request == IOCTL_WDM_MAX_COMMAND) {
		auto param = reinterpret_cast<int *>(arg);

		managarm::fs::GenericIoctlRequest<MemoryAllocator> req(getSysdepsAllocator());
		req.set_command(request);

		auto [offer, send_ioctl_req, send_req, recv_resp] = exchangeMsgsSync(
		    handle,
		    helix_ng::offer(
		        helix_ng::sendBragiHeadOnly(ioctl_req, getSysdepsAllocator()),
		        helix_ng::sendBragiHeadOnly(req, getSysdepsAllocator()),
		        helix_ng::recvInline()
		    )
		);

		HEL_CHECK(offer.error());
		HEL_CHECK(send_ioctl_req.error());
		HEL_CHECK(send_req.error());
		HEL_CHECK(recv_resp.error());

		managarm::fs::GenericIoctlReply<MemoryAllocator> resp(getSysdepsAllocator());
		resp.ParseFromArray(recv_resp.data(), recv_resp.length());
		__ensure(resp.error() == managarm::fs::Errors::SUCCESS);
		*result = resp.result();
		*param = resp.size();
		return 0;
	} else if (request == NVME_IOCTL_ID) {
		managarm::fs::GenericIoctlRequest<MemoryAllocator> req(getSysdepsAllocator());
		req.set_command(request);

		auto [offer, send_ioctl_req, send_req, recv_resp] = exchangeMsgsSync(
		    handle,
		    helix_ng::offer(
		        helix_ng::sendBragiHeadOnly(ioctl_req, getSysdepsAllocator()),
		        helix_ng::sendBragiHeadOnly(req, getSysdepsAllocator()),
		        helix_ng::recvInline()
		    )
		);

		HEL_CHECK(offer.error());
		HEL_CHECK(send_ioctl_req.error());
		HEL_CHECK(send_req.error());
		HEL_CHECK(recv_resp.error());

		managarm::fs::GenericIoctlReply<MemoryAllocator> resp(getSysdepsAllocator());
		resp.ParseFromArray(recv_resp.data(), recv_resp.length());
		__ensure(resp.error() == managarm::fs::Errors::SUCCESS);
		*result = resp.result();
		return 0;
	} else if (request == NVME_IOCTL_ADMIN_CMD) {
		auto param = reinterpret_cast<struct nvme_admin_cmd *>(arg);

		managarm::fs::GenericIoctlRequest<MemoryAllocator> req(getSysdepsAllocator());
		req.set_command(request);

		auto [offer, send_ioctl_req, send_req, send_buffer, send_data, recv_resp, recv_data] =
		    exchangeMsgsSync(
		        handle,
		        helix_ng::offer(
		            helix_ng::sendBragiHeadOnly(ioctl_req, getSysdepsAllocator()),
		            helix_ng::sendBragiHeadOnly(req, getSysdepsAllocator()),
		            helix_ng::sendBuffer(param, sizeof(*param)),
		            helix_ng::sendBuffer(reinterpret_cast<void *>(param->addr), param->data_len),
		            helix_ng::recvInline(),
		            helix_ng::recvBuffer(reinterpret_cast<void *>(param->addr), param->data_len)
		        )
		    );

		HEL_CHECK(offer.error());
		HEL_CHECK(send_ioctl_req.error());
		HEL_CHECK(send_req.error());
		HEL_CHECK(send_buffer.error());
		HEL_CHECK(send_data.error());
		HEL_CHECK(recv_resp.error());
		HEL_CHECK(recv_data.error());

		managarm::fs::GenericIoctlReply<MemoryAllocator> resp(getSysdepsAllocator());
		resp.ParseFromArray(recv_resp.data(), recv_resp.length());
		__ensure(resp.error() == managarm::fs::Errors::SUCCESS);
		*result = resp.result();
		param->result = resp.status();
		return 0;
	} else if (request == FICLONE || request == FICLONERANGE) {
		mlibc::infoLogger() << "\e[35mmlibc: FICLONE/FICLONERANGE are no-ops" << frg::endlog;
		*result = -1;
		return EOPNOTSUPP;
	} else if (request == FS_IOC_GETFLAGS) {
		mlibc::infoLogger() << "\e[35mmlibc: FS_IOC_GETFLAGS is a no-op" << frg::endlog;
		*result = 0;
		return ENOSYS;
	} else if(request == KVM_GET_API_VERSION) {
		managarm::fs::KvmGetApiVersionRequest<MemoryAllocator> req(getSysdepsAllocator());
		auto [offer, send_ioctl_req, send_req, recv_resp] =
		    exchangeMsgsSync(
		        handle,
		        helix_ng::offer(
		            helix_ng::sendBragiHeadOnly(ioctl_req, getSysdepsAllocator()),
		            helix_ng::sendBragiHeadOnly(req, getSysdepsAllocator()),
		            helix_ng::recvInline()
		        )
		    );

		HEL_CHECK(offer.error());
		HEL_CHECK(send_ioctl_req.error());
		HEL_CHECK(send_req.error());
		HEL_CHECK(recv_resp.error());

		managarm::fs::KvmGetApiVersionReply<MemoryAllocator> resp(getSysdepsAllocator());
		resp.ParseFromArray(recv_resp.data(), recv_resp.length());
		*result = resp.api_version();
		return 0;
	} else if(request == KVM_CREATE_VM) {
		auto param = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(arg));

		managarm::fs::KvmCreateVmRequest<MemoryAllocator> req(getSysdepsAllocator());
		req.set_machine_type(param);

		auto [offer, send_ioctl_req, send_req, send_creds, recv_resp] =
		    exchangeMsgsSync(
		        handle,
		        helix_ng::offer(
		            helix_ng::sendBragiHeadOnly(ioctl_req, getSysdepsAllocator()),
		            helix_ng::sendBragiHeadOnly(req, getSysdepsAllocator()),
					helix_ng::imbueCredentials(),
		            helix_ng::recvInline()
		        )
		    );

		HEL_CHECK(offer.error());
		HEL_CHECK(send_ioctl_req.error());
		HEL_CHECK(send_req.error());
		HEL_CHECK(send_creds.error());
		HEL_CHECK(recv_resp.error());

		managarm::fs::KvmCreateVmReply<MemoryAllocator> resp(getSysdepsAllocator());
		resp.ParseFromArray(recv_resp.data(), recv_resp.length());

		if(resp.error() != managarm::fs::Errors::SUCCESS)
			return resp.error() | toErrno;

		*result = resp.vm_fd();
		return 0;
	} else if(request == KVM_GET_VCPU_MMAP_SIZE) {
		managarm::fs::KvmGetVcpuMmapSizeRequest<MemoryAllocator> req(getSysdepsAllocator());
		auto [offer, send_ioctl_req, send_req, recv_resp] =
		    exchangeMsgsSync(
		        handle,
		        helix_ng::offer(
		            helix_ng::sendBragiHeadOnly(ioctl_req, getSysdepsAllocator()),
		            helix_ng::sendBragiHeadOnly(req, getSysdepsAllocator()),
		            helix_ng::recvInline()
		        )
		    );

		HEL_CHECK(offer.error());
		HEL_CHECK(send_ioctl_req.error());
		HEL_CHECK(send_req.error());
		HEL_CHECK(recv_resp.error());

		managarm::fs::KvmGetVcpuMmapSizeReply<MemoryAllocator> resp(getSysdepsAllocator());
		resp.ParseFromArray(recv_resp.data(), recv_resp.length());

		*result = resp.mmap_size();
		return 0;
	} else if(request == KVM_CREATE_VCPU) {
		auto param = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(arg));

		managarm::fs::KvmCreateVcpuRequest<MemoryAllocator> req(getSysdepsAllocator());
		req.set_vcpu_id(param);

		auto [offer, send_ioctl_req, send_req, send_creds, recv_resp] =
		    exchangeMsgsSync(
		        handle,
		        helix_ng::offer(
		            helix_ng::sendBragiHeadOnly(ioctl_req, getSysdepsAllocator()),
		            helix_ng::sendBragiHeadOnly(req, getSysdepsAllocator()),
					helix_ng::imbueCredentials(),
		            helix_ng::recvInline()
		        )
		    );

		HEL_CHECK(offer.error());
		HEL_CHECK(send_ioctl_req.error());
		HEL_CHECK(send_req.error());
		HEL_CHECK(send_creds.error());
		HEL_CHECK(recv_resp.error());

		managarm::fs::KvmCreateVcpuReply<MemoryAllocator> resp(getSysdepsAllocator());
		resp.ParseFromArray(recv_resp.data(), recv_resp.length());

		if(resp.error() != managarm::fs::Errors::SUCCESS)
			return resp.error() | toErrno;

		*result = resp.vcpu_fd();
		return 0;
	} else if(request == KVM_SET_USER_MEMORY_REGION) {
		auto param = reinterpret_cast<struct kvm_userspace_memory_region *>(arg);

		managarm::fs::KvmSetMemoryRegionRequest<MemoryAllocator> req(getSysdepsAllocator());
		req.set_slot(param->slot);
		req.set_flags(param->flags);
		req.set_guest_phys_addr(param->guest_phys_addr);
		req.set_user_addr(param->userspace_addr);
		req.set_memory_size(param->memory_size);

		auto [offer, send_ioctl_req, send_req, send_creds, recv_resp] =
		    exchangeMsgsSync(
		        handle,
		        helix_ng::offer(
		            helix_ng::sendBragiHeadOnly(ioctl_req, getSysdepsAllocator()),
		            helix_ng::sendBragiHeadOnly(req, getSysdepsAllocator()),
					helix_ng::imbueCredentials(),
		            helix_ng::recvInline()
		        )
		    );

		HEL_CHECK(offer.error());
		HEL_CHECK(send_ioctl_req.error());
		HEL_CHECK(send_req.error());
		HEL_CHECK(send_creds.error());
		HEL_CHECK(recv_resp.error());

		managarm::fs::KvmSetMemoryRegionReply<MemoryAllocator> resp(getSysdepsAllocator());
		resp.ParseFromArray(recv_resp.data(), recv_resp.length());

		if(resp.error() != managarm::fs::Errors::SUCCESS)
			return resp.error() | toErrno;

		*result = 0;
		return 0;
	} else if(request == KVM_SET_TSS_ADDR) {
		*result = 0;
		return 0;
	} else if(request == KVM_RUN) {
		managarm::fs::KvmVcpuRunRequest<MemoryAllocator> req(getSysdepsAllocator());
		auto [offer, send_ioctl_req, send_req, recv_resp] =
		    exchangeMsgsSync(
		        handle,
		        helix_ng::offer(
		            helix_ng::sendBragiHeadOnly(ioctl_req, getSysdepsAllocator()),
		            helix_ng::sendBragiHeadOnly(req, getSysdepsAllocator()),
		            helix_ng::recvInline()
		        )
		    );

		HEL_CHECK(offer.error());
		HEL_CHECK(send_ioctl_req.error());
		HEL_CHECK(send_req.error());
		HEL_CHECK(recv_resp.error());

		managarm::fs::KvmVcpuRunReply<MemoryAllocator> resp(getSysdepsAllocator());
		resp.ParseFromArray(recv_resp.data(), recv_resp.length());

		if(resp.error() != managarm::fs::Errors::SUCCESS)
			return resp.error() | toErrno;

		*result = 0;
		return 0;
	} else if(request == KVM_GET_REGS) {
		auto params = reinterpret_cast<struct kvm_regs *>(arg);

		managarm::fs::KvmVcpuGetRegistersRequest<MemoryAllocator> req(getSysdepsAllocator());
		auto [offer, send_ioctl_req, send_req, recv_resp] =
		    exchangeMsgsSync(
		        handle,
		        helix_ng::offer(
					helix_ng::want_lane,
		            helix_ng::sendBragiHeadOnly(ioctl_req, getSysdepsAllocator()),
		            helix_ng::sendBragiHeadOnly(req, getSysdepsAllocator()),
		            helix_ng::recvInline()
		        )
		    );

		HEL_CHECK(offer.error());
		HEL_CHECK(send_ioctl_req.error());
		HEL_CHECK(send_req.error());
		HEL_CHECK(recv_resp.error());

		auto preamble = bragi::read_preamble(recv_resp);

		frg::vector<uint8_t, MemoryAllocator> tail(getSysdepsAllocator());
		tail.resize(preamble.tail_size());

		auto [recv_tail] = exchangeMsgsSync(offer.descriptor().getHandle(),
			helix_ng::recvBuffer(tail.data(), tail.size()));
		HEL_CHECK(recv_tail.error());

		auto resp = bragi::parse_head_tail<managarm::fs::KvmVcpuGetRegistersReply>(recv_resp, tail, getSysdepsAllocator());
		__ensure(resp);

		auto& regs = resp->regs();

		params->rax = regs.rax();
		params->rbx = regs.rbx();
		params->rcx = regs.rcx();
		params->rdx = regs.rdx();
		params->rsi = regs.rsi();
		params->rdi = regs.rdi();
		params->rsp = regs.rsp();
		params->rbp = regs.rbp();
		params->r8 = regs.r8();
		params->r9 = regs.r9();
		params->r10 = regs.r10();
		params->r11 = regs.r11();
		params->r12 = regs.r12();
		params->r13 = regs.r13();
		params->r14 = regs.r14();
		params->r15 = regs.r15();
		params->rip = regs.rip();
		params->rflags = regs.rflags();

		*result = 0;
		return 0;
	} else if(request == KVM_SET_REGS) {
		auto params = reinterpret_cast<struct kvm_regs *>(arg);

		managarm::fs::KvmRegisters<MemoryAllocator> regs(getSysdepsAllocator());
		regs.set_rax(params->rax);
		regs.set_rbx(params->rbx);
		regs.set_rcx(params->rcx);
		regs.set_rdx(params->rdx);
		regs.set_rsi(params->rsi);
		regs.set_rdi(params->rdi);
		regs.set_rsp(params->rsp);
		regs.set_rbp(params->rbp);
		regs.set_r8(params->r8);
		regs.set_r9(params->r9);
		regs.set_r10(params->r10);
		regs.set_r11(params->r11);
		regs.set_r12(params->r12);
		regs.set_r13(params->r13);
		regs.set_r14(params->r14);
		regs.set_r15(params->r15);
		regs.set_rip(params->rip);
		regs.set_rflags(params->rflags);

		managarm::fs::KvmVcpuSetRegistersRequest<MemoryAllocator> req(getSysdepsAllocator());
		req.set_regs(std::move(regs));

		auto [offer, send_ioctl_req, send_req_head, send_req_tail, recv_resp] =
		    exchangeMsgsSync(
		        handle,
		        helix_ng::offer(
		            helix_ng::sendBragiHeadOnly(ioctl_req, getSysdepsAllocator()),
		            helix_ng::sendBragiHeadTail(req, getSysdepsAllocator()),
		            helix_ng::recvInline()
		        )
		    );

		HEL_CHECK(offer.error());
		HEL_CHECK(send_ioctl_req.error());
		HEL_CHECK(send_req_head.error());
		HEL_CHECK(send_req_tail.error());
		HEL_CHECK(recv_resp.error());

		managarm::fs::KvmVcpuSetRegistersReply<MemoryAllocator> resp(getSysdepsAllocator());
		resp.ParseFromArray(recv_resp.data(), recv_resp.length());

		if(resp.error() != managarm::fs::Errors::SUCCESS)
			return resp.error() | toErrno;

		*result = 0;
		return 0;
	} else if(request == KVM_GET_SREGS) {
		auto params = reinterpret_cast<struct kvm_sregs *>(arg);

		managarm::fs::KvmVcpuGetSpecialRegistersRequest<MemoryAllocator> req(getSysdepsAllocator());
		auto [offer, send_ioctl_req, send_req, recv_resp] =
		    exchangeMsgsSync(
		        handle,
		        helix_ng::offer(
					helix_ng::want_lane,
		            helix_ng::sendBragiHeadOnly(ioctl_req, getSysdepsAllocator()),
		            helix_ng::sendBragiHeadOnly(req, getSysdepsAllocator()),
		            helix_ng::recvInline()
		        )
		    );

		HEL_CHECK(offer.error());
		HEL_CHECK(send_ioctl_req.error());
		HEL_CHECK(send_req.error());
		HEL_CHECK(recv_resp.error());

		auto preamble = bragi::read_preamble(recv_resp);

		frg::vector<uint8_t, MemoryAllocator> tail(getSysdepsAllocator());
		tail.resize(preamble.tail_size());

		auto [recv_tail] = exchangeMsgsSync(offer.descriptor().getHandle(),
			helix_ng::recvBuffer(tail.data(), tail.size()));
		HEL_CHECK(recv_tail.error());

		auto resp = bragi::parse_head_tail<managarm::fs::KvmVcpuGetSpecialRegistersReply>(recv_resp, tail, getSysdepsAllocator());
		__ensure(resp);

		auto& regs = resp->regs();

		const auto convertSegment = [](auto &segment) -> struct kvm_segment {
			struct kvm_segment seg;
			memset(&seg, 0, sizeof(seg));
			seg.base = segment.base();
			seg.limit = segment.limit();
			seg.selector = segment.selector();
			seg.type = segment.type();
			seg.present = segment.present();
			seg.dpl = segment.dpl();
			seg.db = segment.db();
			seg.s = segment.s();
			seg.l = segment.l();
			seg.g = segment.g();
			seg.avl = segment.avl();
			return seg;
		};

		const auto convertDtable = [](auto &dtable) -> struct kvm_dtable {
			struct kvm_dtable dtab;
			memset(&dtab, 0, sizeof(dtab));
			dtab.base = dtable.base();
			dtab.limit = dtable.limit();
			return dtab;
		};

		params->cs = convertSegment(regs.cs());
		params->ds = convertSegment(regs.ds());
		params->es = convertSegment(regs.es());
		params->fs = convertSegment(regs.fs());
		params->gs = convertSegment(regs.gs());
		params->ss = convertSegment(regs.ss());
		params->tr = convertSegment(regs.tr());
		params->ldt = convertSegment(regs.ldt());

		params->gdt = convertDtable(regs.gdt());
		params->idt = convertDtable(regs.idt());

		params->cr0 = regs.cr0();
		params->cr2 = regs.cr2();
		params->cr3 = regs.cr3();
		params->cr4 = regs.cr4();
		params->cr8 = regs.cr8();
		params->efer = regs.efer();
		params->apic_base = regs.apic_base();

		size_t copy_size = std::min(sizeof(params->interrupt_bitmap), resp->interrupt_bitmap_size());
		memcpy(params->interrupt_bitmap, resp->interrupt_bitmap().data(), copy_size);

		*result = 0;
		return 0;
	} else if(request == KVM_SET_SREGS) {
		auto params = reinterpret_cast<struct kvm_sregs *>(arg);

		const auto convertSegment = [](struct kvm_segment seg) {
			managarm::fs::KvmSegment<MemoryAllocator> segment(getSysdepsAllocator());
			segment.set_base(seg.base);
			segment.set_limit(seg.limit);
			segment.set_selector(seg.selector);
			segment.set_type(seg.type);
			segment.set_present(seg.present);
			segment.set_dpl(seg.dpl);
			segment.set_db(seg.db);
			segment.set_s(seg.s);
			segment.set_l(seg.l);
			segment.set_g(seg.g);
			segment.set_avl(seg.avl);
			return segment;
		};

		const auto convertDtable = [](struct kvm_dtable dtab) {
			managarm::fs::KvmDtable<MemoryAllocator> dtable(getSysdepsAllocator());
			dtable.set_base(dtab.base);
			dtable.set_limit(dtab.limit);
			return dtable;
		};

		managarm::fs::KvmSpecialRegs<MemoryAllocator> regs(getSysdepsAllocator());
		regs.set_cs(convertSegment(params->cs));
		regs.set_ds(convertSegment(params->ds));
		regs.set_es(convertSegment(params->es));
		regs.set_fs(convertSegment(params->fs));
		regs.set_gs(convertSegment(params->gs));
		regs.set_ss(convertSegment(params->ss));
		regs.set_tr(convertSegment(params->tr));
		regs.set_ldt(convertSegment(params->ldt));

		regs.set_gdt(convertDtable(params->gdt));
		regs.set_idt(convertDtable(params->idt));

		regs.set_cr0(params->cr0);
		regs.set_cr2(params->cr2);
		regs.set_cr3(params->cr3);
		regs.set_cr4(params->cr4);
		regs.set_cr8(params->cr8);
		regs.set_efer(params->efer);
		regs.set_apic_base(params->apic_base);

		frg::vector<uint8_t, MemoryAllocator> interruptBitmap{getSysdepsAllocator()};
		interruptBitmap.resize(sizeof(params->interrupt_bitmap));
		memcpy(interruptBitmap.data(), params->interrupt_bitmap, sizeof(params->interrupt_bitmap));

		managarm::fs::KvmVcpuSetSpecialRegistersRequest<MemoryAllocator> req(getSysdepsAllocator());

		req.set_regs(std::move(regs));
		req.set_interrupt_bitmap(std::move(interruptBitmap));

		auto [offer, send_ioctl_req, send_req_head, send_req_tail, recv_resp] =
		    exchangeMsgsSync(
		        handle,
		        helix_ng::offer(
		            helix_ng::sendBragiHeadOnly(ioctl_req, getSysdepsAllocator()),
		            helix_ng::sendBragiHeadTail(req, getSysdepsAllocator()),
		            helix_ng::recvInline()
		        )
		    );

		HEL_CHECK(offer.error());
		HEL_CHECK(send_ioctl_req.error());
		HEL_CHECK(send_req_head.error());
		HEL_CHECK(send_req_tail.error());
		HEL_CHECK(recv_resp.error());

		managarm::fs::KvmVcpuSetSpecialRegistersReply<MemoryAllocator> resp(getSysdepsAllocator());
		resp.ParseFromArray(recv_resp.data(), recv_resp.length());

		if(resp.error() != managarm::fs::Errors::SUCCESS)
			return resp.error() | toErrno;

		*result = 0;
		return 0;
	}

	mlibc::infoLogger() << "mlibc: Unexpected ioctl with"
	                    << " type: 0x" << frg::hex_fmt(_IOC_TYPE(request)) << ", number: 0x"
	                    << frg::hex_fmt(_IOC_NR(request))
	                    << " (raw request: " << frg::hex_fmt(request) << ")" << frg::endlog;
	__ensure(!"Illegal ioctl request");
	__builtin_unreachable();
}

} // namespace mlibc
