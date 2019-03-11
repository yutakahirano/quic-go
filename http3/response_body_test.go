package http3

import (
	"github.com/golang/mock/gomock"
	"github.com/lucas-clemente/quic-go/internal/mocks"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Response Body", func() {
	var (
		stream *mocks.MockStream
		body   *responseBody
	)

	BeforeEach(func() {
		stream = mocks.NewMockStream(mockCtrl)
		body = &responseBody{stream}
	})

	It("calls CancelRead when closing", func() {
		stream.EXPECT().CancelRead(gomock.Any())
		Expect(body.Close()).To(Succeed())
	})
})
