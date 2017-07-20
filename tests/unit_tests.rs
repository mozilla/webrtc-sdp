extern crate rsdparsa;

#[test]
fn parse_minimal_sdp() {
    let sdp = "v=0\r\n
o=- 0 0 IN IP4 0.0.0.0\r\n
s=-\r\n
t=0 0\r\n
m=audio 0 UDP/TLS/RTP/SAVPF 0\r\n";
    let sdp_res = rsdparsa::parse_sdp(sdp, true);
    assert!(sdp_res.is_ok());
    let sdp_opt = sdp_res.ok();
    assert!(sdp_opt.is_some());
    let sdp = sdp_opt.unwrap();
    assert_eq!(sdp.version, 0);
    assert_eq!(sdp.session, "-");
    assert!(sdp.connection.is_none());
    assert_eq!(sdp.attribute.len(), 0);
    assert_eq!(sdp.media.len(), 1);

    let msection = &(sdp.media[0]);
    assert_eq!(*msection.get_type(),
               rsdparsa::media_type::SdpMediaValue::Audio);
    assert_eq!(msection.get_port(), 0);
    assert_eq!(*msection.get_proto(),
               rsdparsa::media_type::SdpProtocolValue::UdpTlsRtpSavpf);
    assert!(!msection.has_attributes());
    assert!(!msection.has_bandwidth());
    assert!(!msection.has_connection());
    assert!(msection.get_connection().is_none());
}

#[test]
fn parse_minimal_sdp_with_emtpy_lines() {
    let sdp = "v=0\r\n
\r\n
o=- 0 0 IN IP4 0.0.0.0\r\n
 \r\n
s=-\r\n
t=0 0\r\n
m=audio 0 UDP/TLS/RTP/SAVPF 0\r\n";
    let sdp_res = rsdparsa::parse_sdp(sdp, false);
    assert!(sdp_res.is_ok());
    let sdp_opt = sdp_res.ok();
    assert!(sdp_opt.is_some());
    let sdp = sdp_opt.unwrap();
    assert_eq!(sdp.version, 0);
    assert_eq!(sdp.session, "-");
}

#[test]
fn parse_minimal_sdp_with_most_session_types() {
    let sdp = "v=0\r\n
o=- 0 0 IN IP4 0.0.0.0\r\n
s=-\r\n
t=0 0\r\n
b=AS:1\r\n
b=CT:123\r\n
b=TIAS:12345\r\n
c=IN IP4 0.0.0.0\r\n
a=ice-options:trickle\r\n
m=audio 0 UDP/TLS/RTP/SAVPF 0\r\n";
    let sdp_res = rsdparsa::parse_sdp(sdp, false);
    assert!(sdp_res.is_ok());
    let sdp_opt = sdp_res.ok();
    assert!(sdp_opt.is_some());
    let sdp = sdp_opt.unwrap();
    assert_eq!(sdp.version, 0);
    assert_eq!(sdp.session, "-");
    assert!(sdp.get_connection().is_some());
}

#[test]
fn parse_firefox_audio_offer() {
    let sdp = "v=0\r\n
o=mozilla...THIS_IS_SDPARTA-52.0a1 506705521068071134 0 IN IP4 0.0.0.0\r\n
s=-\r\n
t=0 0\r\n
a=fingerprint:sha-256 CD:34:D1:62:16:95:7B:B7:EB:74:E2:39:27:97:EB:0B:23:73:AC:BC:BF:2F:E3:91:CB:57:A9:9D:4A:A2:0B:40\r\n
a=group:BUNDLE sdparta_0\r\n
a=ice-options:trickle\r\n
a=msid-semantic:WMS *\r\n
m=audio 9 UDP/TLS/RTP/SAVPF 109 9 0 8\r\n
c=IN IP4 0.0.0.0\r\n
a=sendrecv\r\n
a=extmap:1/sendonly urn:ietf:params:rtp-hdrext:ssrc-audio-level\r\n
a=fmtp:109 maxplaybackrate=48000;stereo=1;useinbandfec=1\r\n
a=ice-pwd:e3baa26dd2fa5030d881d385f1e36cce\r\n
a=ice-ufrag:58b99ead\r\n
a=mid:sdparta_0\r\n
a=msid:{5a990edd-0568-ac40-8d97-310fc33f3411} {218cfa1c-617d-2249-9997-60929ce4c405}\r\n
a=rtcp-mux\r\n
a=rtpmap:109 opus/48000/2\r\n
a=rtpmap:9 G722/8000/1\r\n
a=rtpmap:0 PCMU/8000\r\n
a=rtpmap:8 PCMA/8000\r\n
a=setup:actpass\r\n
a=ssrc:2655508255 cname:{735484ea-4f6c-f74a-bd66-7425f8476c2e}\r\n";
    let sdp_res = rsdparsa::parse_sdp(sdp, true);
    assert!(sdp_res.is_ok());
    let sdp_opt = sdp_res.ok();
    assert!(sdp_opt.is_some());
    let sdp = sdp_opt.unwrap();
    assert_eq!(sdp.version, 0);
    assert_eq!(sdp.media.len(), 1);

    let msection = &(sdp.media[0]);
    assert_eq!(*msection.get_type(),
               rsdparsa::media_type::SdpMediaValue::Audio);
    assert_eq!(msection.get_port(), 9);
    assert_eq!(*msection.get_proto(),
               rsdparsa::media_type::SdpProtocolValue::UdpTlsRtpSavpf);
    assert!(msection.has_attributes());
    assert!(msection.has_connection());
    assert!(msection.get_connection().is_some());
    assert!(!msection.has_bandwidth());
}

#[test]
fn parse_firefox_video_offer() {
    let sdp = "v=0\r\n
o=mozilla...THIS_IS_SDPARTA-52.0a1 506705521068071134 0 IN IP4 0.0.0.0\r\n
s=-\r\n
t=0 0\r\n
a=fingerprint:sha-256 CD:34:D1:62:16:95:7B:B7:EB:74:E2:39:27:97:EB:0B:23:73:AC:BC:BF:2F:E3:91:CB:57:A9:9D:4A:A2:0B:40\r\n
a=group:BUNDLE sdparta_2\r\n
a=ice-options:trickle\r\n
a=msid-semantic:WMS *\r\n
m=video 9 UDP/TLS/RTP/SAVPF 126 120 97\r\n
c=IN IP4 0.0.0.0\r\n
a=recvonly\r\n
a=fmtp:126 profile-level-id=42e01f;level-asymmetry-allowed=1;packetization-mode=1\r\n
a=fmtp:120 max-fs=12288;max-fr=60\r\n
a=fmtp:97 profile-level-id=42e01f;level-asymmetry-allowed=1\r\n
a=ice-pwd:e3baa26dd2fa5030d881d385f1e36cce\r\n
a=ice-ufrag:58b99ead\r\n
a=mid:sdparta_2\r\n
a=rtcp-fb:126 nack\r\n
a=rtcp-fb:126 nack pli\r\n
a=rtcp-fb:126 ccm fir\r\n
a=rtcp-fb:126 goog-remb\r\n
a=rtcp-fb:120 nack\r\n
a=rtcp-fb:120 nack pli\r\n
a=rtcp-fb:120 ccm fir\r\n
a=rtcp-fb:120 goog-remb\r\n
a=rtcp-fb:97 nack\r\n
a=rtcp-fb:97 nack pli\r\n
a=rtcp-fb:97 ccm fir\r\n
a=rtcp-fb:97 goog-remb\r\n
a=rtcp-mux\r\n
a=rtpmap:126 H264/90000\r\n
a=rtpmap:120 VP8/90000\r\n
a=rtpmap:97 H264/90000\r\n
a=setup:actpass\r\n
a=ssrc:2709871439 cname:{735484ea-4f6c-f74a-bd66-7425f8476c2e}";
    let sdp_res = rsdparsa::parse_sdp(sdp, true);
    assert!(sdp_res.is_ok());
    let sdp_opt = sdp_res.ok();
    assert!(sdp_opt.is_some());
    let sdp = sdp_opt.unwrap();
    assert_eq!(sdp.version, 0);
    assert_eq!(sdp.media.len(), 1);

    let msection = &(sdp.media[0]);
    assert_eq!(*msection.get_type(),
               rsdparsa::media_type::SdpMediaValue::Video);
    assert_eq!(msection.get_port(), 9);
    assert_eq!(*msection.get_proto(),
               rsdparsa::media_type::SdpProtocolValue::UdpTlsRtpSavpf);
}

#[test]
fn parse_firefox_datachannel_offer() {
    let sdp = "v=0\r\n
o=mozilla...THIS_IS_SDPARTA-52.0a2 3327975756663609975 0 IN IP4 0.0.0.0\r\n
s=-\r\n
t=0 0\r\n
a=sendrecv\r\n
a=fingerprint:sha-256 AC:72:CB:D6:1E:A3:A3:B0:E7:97:77:25:03:4B:5B:FF:19:6C:02:C6:93:7D:EB:5C:81:6F:36:D9:02:32:F8:23\r\n
a=ice-options:trickle\r\n
a=msid-semantic:WMS *\r\n
m=application 49760 DTLS/SCTP 5000\r\n
c=IN IP4 172.16.156.106\r\n
a=candidate:0 1 UDP 2122252543 172.16.156.106 49760 typ host\r\n
a=sendrecv\r\n
a=end-of-candidates\r\n
a=ice-pwd:24f485c580129b36447b65df77429a82\r\n
a=ice-ufrag:4cba30fe\r\n
a=mid:sdparta_0\r\n
a=sctpmap:5000 webrtc-datachannel 256\r\n
a=setup:active\r\n
a=ssrc:3376683177 cname:{62f78ee0-620f-a043-86ca-b69f189f1aea}\r\n";
    let sdp_res = rsdparsa::parse_sdp(sdp, true);
    assert!(sdp_res.is_ok());
    let sdp_opt = sdp_res.ok();
    assert!(sdp_opt.is_some());
    let sdp = sdp_opt.unwrap();
    assert_eq!(sdp.version, 0);
    assert_eq!(sdp.media.len(), 1);

    let msection = &(sdp.media[0]);
    assert_eq!(*msection.get_type(),
               rsdparsa::media_type::SdpMediaValue::Application);
    assert_eq!(msection.get_port(), 49760);
    assert_eq!(*msection.get_proto(),
               rsdparsa::media_type::SdpProtocolValue::DtlsSctp);
}

#[test]
fn parse_chrome_audio_video_offer() {
    let sdp = "v=0\r\n
o=- 3836772544440436510 2 IN IP4 127.0.0.1\r\n
s=-\r\n
t=0 0\r\n
a=group:BUNDLE audio video\r\n
a=msid-semantic: WMS HWpbmTmXleVSnlssQd80bPuw9cxQFroDkkBP\r\n
m=audio 9 UDP/TLS/RTP/SAVPF 111 103 104 9 0 8 106 105 13 126\r\n
c=IN IP4 0.0.0.0\r\n
a=rtcp:9 IN IP4 0.0.0.0\r\n
a=ice-ufrag:A4by\r\n
a=ice-pwd:Gfvb2rbYMiW0dZz8ZkEsXICs\r\n
a=fingerprint:sha-256 15:B0:92:1F:C7:40:EE:22:A6:AF:26:EF:EA:FF:37:1D:B3:EF:11:0B:8B:73:4F:01:7D:C9:AE:26:4F:87:E0:95\r\n
a=setup:actpass\r\n
a=mid:audio\r\n
a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\r\n
a=sendrecv\r\n
a=rtcp-mux\r\n
a=rtpmap:111 opus/48000/2\r\n
a=rtcp-fb:111 transport-cc\r\n
a=fmtp:111 minptime=10;useinbandfec=1\r\n
a=rtpmap:103 ISAC/16000\r\n
a=rtpmap:104 ISAC/32000\r\n
a=rtpmap:9 G722/8000\r\n
a=rtpmap:0 PCMU/8000\r\n
a=rtpmap:8 PCMA/8000\r\n
a=rtpmap:106 CN/32000\r\n
a=rtpmap:105 CN/16000\r\n
a=rtpmap:13 CN/8000\r\n
a=rtpmap:126 telephone-event/8000\r\n
a=ssrc:162559313 cname:qPTZ+BI+42mgbOi+\r\n
a=ssrc:162559313 msid:HWpbmTmXleVSnlssQd80bPuw9cxQFroDkkBP f6188af5-d8d6-462c-9c75-f12bc41fe322\r\n
a=ssrc:162559313 mslabel:HWpbmTmXleVSnlssQd80bPuw9cxQFroDkkBP\r\n
a=ssrc:162559313 label:f6188af5-d8d6-462c-9c75-f12bc41fe322\r\n
m=video 9 UDP/TLS/RTP/SAVPF 100 101 107 116 117 96 97 99 98\r\n
c=IN IP4 0.0.0.0\r\n
a=rtcp:9 IN IP4 0.0.0.0\r\n
a=ice-ufrag:A4by\r\n
a=ice-pwd:Gfvb2rbYMiW0dZz8ZkEsXICs\r\n
a=fingerprint:sha-256 15:B0:92:1F:C7:40:EE:22:A6:AF:26:EF:EA:FF:37:1D:B3:EF:11:0B:8B:73:4F:01:7D:C9:AE:26:4F:87:E0:95\r\n
a=setup:actpass\r\n
a=mid:video\r\n
a=extmap:2 urn:ietf:params:rtp-hdrext:toffset\r\n
a=extmap:3 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time\r\n
a=extmap:4 urn:3gpp:video-orientation\r\n
a=extmap:5 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01\r\n
a=extmap:6 http://www.webrtc.org/experiments/rtp-hdrext/playout-delay\r\n
a=sendrecv\r\n
a=rtcp-mux\r\n
a=rtcp-rsize\r\n
a=rtpmap:100 VP8/90000\r\n
a=rtcp-fb:100 ccm fir\r\n
a=rtcp-fb:100 nack\r\n
a=rtcp-fb:100 nack pli\r\n
a=rtcp-fb:100 goog-remb\r\n
a=rtcp-fb:100 transport-cc\r\n
a=rtpmap:101 VP9/90000\r\n
a=rtcp-fb:101 ccm fir\r\n
a=rtcp-fb:101 nack\r\n
a=rtcp-fb:101 nack pli\r\n
a=rtcp-fb:101 goog-remb\r\n
a=rtcp-fb:101 transport-cc\r\n
a=rtpmap:107 H264/90000\r\n
a=rtcp-fb:107 ccm fir\r\n
a=rtcp-fb:107 nack\r\n
a=rtcp-fb:107 nack pli\r\n
a=rtcp-fb:107 goog-remb\r\n
a=rtcp-fb:107 transport-cc\r\n
a=fmtp:107 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f\r\n
a=rtpmap:116 red/90000\r\n
a=rtpmap:117 ulpfec/90000\r\n
a=rtpmap:96 rtx/90000\r\n
a=fmtp:96 apt=100\r\n
a=rtpmap:97 rtx/90000\r\n
a=fmtp:97 apt=101\r\n
a=rtpmap:99 rtx/90000\r\n
a=fmtp:99 apt=107\r\n
a=rtpmap:98 rtx/90000\r\n
a=fmtp:98 apt=116\r\n
a=ssrc-group:FID 3156517279 2673335628\r\n
a=ssrc:3156517279 cname:qPTZ+BI+42mgbOi+\r\n
a=ssrc:3156517279 msid:HWpbmTmXleVSnlssQd80bPuw9cxQFroDkkBP b6ec5178-c611-403f-bbec-3833ed547c09\r\n
a=ssrc:3156517279 mslabel:HWpbmTmXleVSnlssQd80bPuw9cxQFroDkkBP\r\n
a=ssrc:3156517279 label:b6ec5178-c611-403f-bbec-3833ed547c09\r\n
a=ssrc:2673335628 cname:qPTZ+BI+42mgbOi+\r\n
a=ssrc:2673335628 msid:HWpbmTmXleVSnlssQd80bPuw9cxQFroDkkBP b6ec5178-c611-403f-bbec-3833ed547c09\r\n
a=ssrc:2673335628 mslabel:HWpbmTmXleVSnlssQd80bPuw9cxQFroDkkBP\r\n
a=ssrc:2673335628 label:b6ec5178-c611-403f-bbec-3833ed547c09\r\n";
    let sdp_res = rsdparsa::parse_sdp(sdp, true);
    assert!(sdp_res.is_ok());
    let sdp_opt = sdp_res.ok();
    assert!(sdp_opt.is_some());
    let sdp = sdp_opt.unwrap();
    assert_eq!(sdp.version, 0);
    assert_eq!(sdp.media.len(), 2);

    let msection1 = &(sdp.media[0]);
    assert_eq!(*msection1.get_type(),
               rsdparsa::media_type::SdpMediaValue::Audio);
    assert_eq!(msection1.get_port(), 9);
    assert_eq!(*msection1.get_proto(),
               rsdparsa::media_type::SdpProtocolValue::UdpTlsRtpSavpf);
    assert!(msection1.has_attributes());
    assert!(msection1.has_connection());
    assert!(!msection1.has_bandwidth());

    let msection2 = &(sdp.media[1]);
    assert_eq!(*msection2.get_type(),
               rsdparsa::media_type::SdpMediaValue::Video);
    assert_eq!(msection2.get_port(), 9);
    assert_eq!(*msection2.get_proto(),
               rsdparsa::media_type::SdpProtocolValue::UdpTlsRtpSavpf);
    assert!(msection2.has_attributes());
    assert!(msection2.has_connection());
    assert!(!msection2.has_bandwidth());
}

#[test]
fn parse_firefox_simulcast_offer() {
    let sdp = "v=0\r\n
o=mozilla...THIS_IS_SDPARTA-55.0a1 983028567300715536 0 IN IP4 0.0.0.0\r\n
s=-\r\n
t=0 0\r\n
a=fingerprint:sha-256 68:42:13:88:B6:C1:7D:18:79:07:8A:C6:DC:28:D6:DC:DD:E3:C9:41:E7:80:A7:FE:02:65:FB:76:A0:CD:58:ED\r\n
a=ice-options:trickle\r\n
a=msid-semantic:WMS *\r\n
m=video 9 UDP/TLS/RTP/SAVPF 120 121 126 97\r\n
c=IN IP4 0.0.0.0\r\n
a=sendrecv\r\n
a=extmap:1 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time\r\n
a=extmap:2 urn:ietf:params:rtp-hdrext:toffset\r\n
a=extmap:3/sendonly urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id\r\n
a=fmtp:126 profile-level-id=42e01f;level-asymmetry-allowed=1;packetization-mode=1\r\n
a=fmtp:97 profile-level-id=42e01f;level-asymmetry-allowed=1\r\n
a=fmtp:120 max-fs=12288;max-fr=60\r\n
a=fmtp:121 max-fs=12288;max-fr=60\r\n
a=ice-pwd:4af388405d558b91f5ba6c2c48f161bf\r\n
a=ice-ufrag:ce1ac488\r\n
a=mid:sdparta_0\r\n
a=msid:{fb6d1fa3-d993-f244-a0fe-d9fb99214c23} {8be9a0f7-9272-6c42-90f3-985d55bd8de5}\r\n
a=rid:foo send\r\n
a=rid:bar send\r\n
a=rtcp-fb:120 nack\r\n
a=rtcp-fb:120 nack pli\r\n
a=rtcp-fb:120 ccm fir\r\n
a=rtcp-fb:120 goog-remb\r\n
a=rtcp-fb:121 nack\r\n
a=rtcp-fb:121 nack pli\r\n
a=rtcp-fb:121 ccm fir\r\n
a=rtcp-fb:121 goog-remb\r\n
a=rtcp-fb:126 nack\r\n
a=rtcp-fb:126 nack pli\r\n
a=rtcp-fb:126 ccm fir\r\n
a=rtcp-fb:126 goog-remb\r\n
a=rtcp-fb:97 nack\r\n
a=rtcp-fb:97 nack pli\r\n
a=rtcp-fb:97 ccm fir\r\n
a=rtcp-fb:97 goog-remb\r\n
a=rtcp-mux\r\n
a=rtpmap:120 VP8/90000\r\n
a=rtpmap:121 VP9/90000\r\n
a=rtpmap:126 H264/90000\r\n
a=rtpmap:97 H264/90000\r\n
a=setup:actpass\r\n
a=simulcast: send rid=foo;bar\r\n
a=ssrc:2988475468 cname:{77067f00-2e8d-8b4c-8992-cfe338f56851}\r\n
a=ssrc:1649784806 cname:{77067f00-2e8d-8b4c-8992-cfe338f56851}\r\n";
    let sdp_res = rsdparsa::parse_sdp(sdp, true);
    assert!(sdp_res.is_ok());
    let sdp_opt = sdp_res.ok();
    assert!(sdp_opt.is_some());
    let sdp = sdp_opt.unwrap();
    assert_eq!(sdp.version, 0);
    assert_eq!(sdp.media.len(), 1);
}

#[test]
fn parse_firefox_simulcast_answer() {
    let sdp = "v=0\r\n
o=mozilla...THIS_IS_SDPARTA-55.0a1 7548296603161351381 0 IN IP4 0.0.0.0\r\n
s=-\r\n
t=0 0\r\n
a=fingerprint:sha-256 B1:47:49:4F:7D:83:03:BE:E9:FC:73:A3:FB:33:38:40:0B:3B:6A:56:78:EB:EE:D5:6D:2D:D5:3A:B6:13:97:E7\r\n
a=ice-options:trickle\r\n
a=msid-semantic:WMS *\r\n
m=video 9 UDP/TLS/RTP/SAVPF 120\r\n
c=IN IP4 0.0.0.0\r\n
a=recvonly\r\n
a=extmap:1 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time\r\n
a=extmap:2 urn:ietf:params:rtp-hdrext:toffset\r\n
a=fmtp:120 max-fs=12288;max-fr=60\r\n
a=ice-pwd:c886e2caf2ae397446312930cd1afe51\r\n
a=ice-ufrag:f57396c0\r\n
a=mid:sdparta_0\r\n
a=rtcp-fb:120 nack\r\n
a=rtcp-fb:120 nack pli\r\n
a=rtcp-fb:120 ccm fir\r\n
a=rtcp-fb:120 goog-remb\r\n
a=rtcp-mux\r\n
a=rtpmap:120 VP8/90000\r\n
a=setup:active\r\n
a=ssrc:2564157021 cname:{cae1cd32-7433-5b48-8dc8-8e3f8b2f96cd}\r\n
a=simulcast: recv rid=foo;bar\r\n
a=rid:foo recv\r\n
a=rid:bar recv\r\n
a=extmap:3/recvonly urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id\r\n";
    let sdp_res = rsdparsa::parse_sdp(sdp, true);
    assert!(sdp_res.is_ok());
    let sdp_opt = sdp_res.ok();
    assert!(sdp_opt.is_some());
    let sdp = sdp_opt.unwrap();
    assert_eq!(sdp.version, 0);
    assert_eq!(sdp.media.len(), 1);
}
