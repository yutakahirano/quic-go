package mocks

//go:generate sh -c "mockgen -package mocks -destination stream.go github.com/lucas-clemente/quic-go Stream && goimports -w stream.go"
//go:generate sh -c "mockgen -package mocks -destination session.go github.com/lucas-clemente/quic-go Session && goimports -w session.go"
//go:generate sh -c "../mockgen_internal.sh mocks sealer.go github.com/lucas-clemente/quic-go/internal/handshake Sealer"
//go:generate sh -c "../mockgen_internal.sh mocks opener.go github.com/lucas-clemente/quic-go/internal/handshake Opener"
//go:generate sh -c "../mockgen_internal.sh mocks crypto_setup.go github.com/lucas-clemente/quic-go/internal/handshake CryptoSetup"
//go:generate sh -c "../mockgen_internal.sh mocks stream_flow_controller.go github.com/lucas-clemente/quic-go/internal/flowcontrol StreamFlowController"
//go:generate sh -c "../mockgen_internal.sh mockackhandler ackhandler/sent_packet_handler.go github.com/lucas-clemente/quic-go/internal/ackhandler SentPacketHandler"
//go:generate sh -c "../mockgen_internal.sh mockackhandler ackhandler/received_packet_handler.go github.com/lucas-clemente/quic-go/internal/ackhandler ReceivedPacketHandler"
//go:generate sh -c "../mockgen_internal.sh mocks congestion.go github.com/lucas-clemente/quic-go/internal/congestion SendAlgorithm"
//go:generate sh -c "../mockgen_internal.sh mocks connection_flow_controller.go github.com/lucas-clemente/quic-go/internal/flowcontrol ConnectionFlowController"
