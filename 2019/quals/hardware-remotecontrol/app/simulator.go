// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Author: zuan@google.com

package main

import (
	"math"
	"math/rand"
	"time"

	"github.com/go-daq/crc8"
)

// DefaultSampleRate is the sample rate of our simulation
const DefaultSampleRate = 150.0 * 1000.0

// IOTBaudRate is the Baud rate of our protocol
const IOTBaudRate = 1.785 * 1000.0

// CarrierFreq is the carrier frequency of the Infrared signal
const CarrierFreq = 38.0 * 1000.0

// IRRSignalDetectorFc is the low pass filter Fc for signal strength detector in IR Receiver
const IRRSignalDetectorFc = 15.0 * 1000.0

// IRRBandpassFc is the Fc for the bandpass filter in IR Receiver to filter out everything but the IR carrier signal
const IRRBandpassFc = CarrierFreq

// IRRRecoveryFc is the Fc of the output low pass filter in IR Receiver
const IRRRecoveryFc = 8.0 * 1000.0

// Crc8Poly is the polnomial for CRC8 calculation. We are using CRC-8-CCITT, x^8+x^2+x^1+1.
const Crc8Poly = 0x07

// CommandPing is the command byte for Ping command
const CommandPing = 0x01

// CommandGetTemp is the command byte for Get Temperature command
const CommandGetTemp = 0x10

// CommandGetHumidity is the command byte for Get Humidity command
const CommandGetHumidity = 0x11

// CommandGetCO2 is the command byte for Get CO2 reading command
const CommandGetCO2 = 0x12

// CommandGetSmokeDetector is the command byte for Get Smoke Detector status command
const CommandGetSmokeDetector = 0x13

// CommandSetTime is the command byte for Set Time command
const CommandSetTime = 0x20

// CommandSystemVersion is the command byte for Get System Version command
const CommandSystemVersion = 0x30

// CommandReply is the flag for indicating that the command byte is the reply not the request
const CommandReply = 0x80

// If this bit is set, then it's replying

func min(a int, b int) int {
	if a > b {
		return b
	}
	return a
}

func max(a int, b int) int {
	if a > b {
		return a
	}
	return b
}

// SchmidtTrigger is a Schmidt Trigger module
type SchmidtTrigger struct {
	tHi float64
	tLo float64
	// tHi -> rising edge threshold (Low to high)

	state int
	// 0 for lo, 1 for hi
}

// NewSchmidtTrigger will create a new Schmidt Trigger module, specified by tLo (high to low transition level) and tHi (low to high transition level)
func NewSchmidtTrigger(tLo float64, tHi float64) *SchmidtTrigger {
	return &SchmidtTrigger{
		tLo:   tLo,
		tHi:   tHi,
		state: 0,
	}
}

func (x *SchmidtTrigger) step(inV float64) int {
	if x.state == 0 && x.tHi < inV {
		x.state = 1
	} else if x.state == 1 && x.tLo > inV {
		x.state = 0
	}

	if x.state == 1 {
		return 1
	}
	return 0
}

// IRTransmitter is an IR Transmitter module
type IRTransmitter struct {
	txPhase float64
	// Phase of the 38kHz Carrier, between 0 and 1

	sim *Simulator
	// The parent simulator
}

// NewIRTransmitter will create a new IR transmitter
func NewIRTransmitter(s *Simulator) *IRTransmitter {
	return &IRTransmitter{
		txPhase: s.rand.Float64(),
		sim:     s,
	}
}

func (t *IRTransmitter) step(inV float64) float64 {
	// Generate the 38kHz carrier
	hubCar := 0.0
	hubCarTp := t.sim.currentTime * CarrierFreq // Total phase
	_, hubCarPhaseFrac := math.Modf(hubCarTp)
	if hubCarPhaseFrac < 0.5 {
		hubCar = 1.0
	}
	return hubCar * inV
}

// IRReceiver is an IR Receiver module
type IRReceiver struct {
	sim *Simulator
	// The parent simulator

	dt float64
	// Inverse sample rate

	sdAlpha float64
	// Signal detector alpha, used in the low pass filter

	sdYi float64
	// Previous/Current output of signal strength detector

	bpf1x1 float64
	bpf1x2 float64
	bpf1y1 float64
	bpf1y2 float64
	bpf2x1 float64
	bpf2x2 float64
	bpf2y1 float64
	bpf2y2 float64
	// Bandpass filter x[n-1]... y[n-2]
	// There are 2 bandpass filters

	bpfQ  float64
	bpfA0 float64
	bpfA1 float64
	bpfA2 float64
	bpfB1 float64
	bpfB2 float64
	// Bandpass filter coefficients

	rlpAlpha float64
	// Recovery Low Pass alpha

	rlpYi float64
	// Previous/Current output of recovery

	outIO *SchmidtTrigger
	// Output I/O
}

// NewIRReceiver will create a new IR Receiver module
func NewIRReceiver(s *Simulator) *IRReceiver {
	x := IRReceiver{
		sim:   s,
		outIO: NewSchmidtTrigger(1.0, 2.0),
	}

	// Initialize the low pass filters
	x.dt = 1.0 / (s.sampleRate)
	x.sdAlpha = (2.0 * math.Pi * x.dt * IRRSignalDetectorFc) / (2.0*math.Pi*x.dt*IRRSignalDetectorFc + 1.0)
	x.sdYi = 0.0

	x.rlpAlpha = (2.0 * math.Pi * x.dt * IRRRecoveryFc) / (2.0*math.Pi*x.dt*IRRRecoveryFc + 1.0)
	x.rlpYi = 0.0

	/*
	  We implement a typical second order bandpass filter with the following s-domain transfer function:
	  (w/Q*s/(s^2+w/Q*s+w^2))

	  The digital filter coefficients are computed with the following sage math script:
	  var('w s z Q T')
	  H = (w/Q*s/(s^2+w/Q*s+w^2)).subs(s=(2/T)*(1-z^-1)/(1+z^-1)).expand().simplify()
	  p = lambda x: x.numerator().expand().simplify().coefficients(x=z, sparse=False)
	  A, B = p(H.numerator()), p(H.denominator())
	  A = [x/B[0] for x in A]
	  B = [-x/B[0] for x in B]
	  [A, B]

	  The result is:
	  c = (Q*T^2*w^2 + 2*T*w + 4*Q)
	  a0 = 2*T*w/c
	  a1 = 0
	  a2 = -2*T*w/c = -a0
	  b1 = -2*(Q*T^2*w^2 - 4*Q)/c
	  b2 = -(Q*T^2*w^2 - 2*T*w + 4*Q)/c

	*/
	x.bpfQ = 0.5
	Q := x.bpfQ
	T := x.dt
	w := IRRBandpassFc * 2.0 * math.Pi

	c := Q*T*T*w*w + 2.0*T*w + 4.0*Q
	x.bpfA0 = 2.0 * T * w / c
	x.bpfA1 = 0.0
	x.bpfA2 = -x.bpfA0
	x.bpfB1 = -2.0 * (Q*T*T*w*w - 4.0*Q) / c
	x.bpfB2 = -(Q*T*T*w*w - 2.0*T*w + 4.0*Q) / c

	x.bpf1x1 = 0.0
	x.bpf1x2 = 0.0
	x.bpf1y1 = 0.0
	x.bpf1y2 = 0.0

	x.bpf2x1 = 0.0
	x.bpf2x2 = 0.0
	x.bpf2y1 = 0.0
	x.bpf2y2 = 0.0
	return &x
}

func (r *IRReceiver) step(inL float64) int {
	// Pass the input through a Automatic Gain Control Amplifier first

	// Pass the input through a low pass filter to get the current signal strength
	r.sdYi = r.sdYi*(1.0-r.sdAlpha) + r.sdAlpha*inL

	// Normalized input illuminance
	inLn := inL / r.sdYi

	// Pass it through the bandpass filter
	bpf1Out := inLn*r.bpfA0 + r.bpf1x1*r.bpfA1 + r.bpf1x2*r.bpfA2 + r.bpf1y1*r.bpfB1 + r.bpf1y2*r.bpfB2

	// Update the bandpass filter
	r.bpf1x2 = r.bpf1x1
	r.bpf1x1 = inLn
	r.bpf1y2 = r.bpf1y1
	r.bpf1y1 = bpf1Out

	bpf1Out = bpf1Out * (2.0*r.bpfQ + 1)

	// Pass it through the second bandpass filter
	bpf2Out := bpf1Out*r.bpfA0 + r.bpf2x1*r.bpfA1 + r.bpf2x2*r.bpfA2 + r.bpf2y1*r.bpfB1 + r.bpf2y2*r.bpfB2

	// Update the bandpass filter
	r.bpf2x2 = r.bpf2x1
	r.bpf2x1 = bpf1Out
	r.bpf2y2 = r.bpf2y1
	r.bpf2y1 = bpf2Out

	bpf2Out = bpf2Out * (2.0*r.bpfQ + 1)

	bpfOutAbs := math.Abs(bpf2Out)

	r.rlpYi = r.rlpYi*(1.0-r.rlpAlpha) + r.rlpAlpha*bpfOutAbs

	return r.outIO.step(r.rlpYi)
}

// BitStreamTx is a bit stream transmitter module. Given a bitstream slice it'll output the corresponding value at the specified time.
type BitStreamTx struct {
	txData []int
	// Contains the data to transmit, position i holds the data to transmit at time
	// dt*i to dt*(i+1). That is, at time t, we transmit the value txData[floor(t*(1/dt))]

	txPos int
	// The position in txData from which we'll append data to transmit

	sim *Simulator
	// The parent simulator

	crcTable *crc8.Table
}

// NewBitStreamTx will create a new bit stream transmitter module
func NewBitStreamTx(sim *Simulator) *BitStreamTx {
	return &BitStreamTx{
		sim:      sim,
		txData:   make([]int, int(sim.simulationTime*IOTBaudRate+32)),
		txPos:    2,
		crcTable: crc8.MakeTable(Crc8Poly),
	}
}

func (x *BitStreamTx) appendData(data []int) {
	// Calculate the current index
	ididxF := x.sim.currentTime * IOTBaudRate // The float value
	ididx := int(ididxF)

	x.txPos = max(ididx+3, x.txPos) // Leave 3 baud between current transmission and the next

	for i := 0; i < min(len(x.txData)-x.txPos, len(data)); i++ {
		x.txData[x.txPos+i] = data[i]
	}
	x.txPos += len(data) + 8 // Leave some space at the end
}

func (x *BitStreamTx) appendPacket(data []byte) {
	// The first byte is the command, the rest is parameter to the command
	res := make([]byte, len(data)+3) // One extra byte for 0x55, length, and CRC-8
	res[0] = 0x55
	res[1] = uint8(len(res))
	for i, element := range data {
		res[i+2] = element
	}

	crcres := crc8.Checksum(res[0:len(data)+2], x.crcTable)
	res[len(res)-1] = crcres

	resb := make([]int, len(res)*8)
	for i, element := range res {
		cb := int(element) // Current byte
		b := 1             // Shifting bit
		for j := 0; j < 8; j++ {
			resb[i*8+j] = 0
			if cb&b != 0 {
				resb[i*8+j] = 1
			}
			b = b << 1
		}
	}
	x.appendData(resb)
}

func (x *BitStreamTx) step() int {
	ididxF := x.sim.currentTime * IOTBaudRate // The float value
	ididx := int(ididxF)
	return x.txData[ididx]
}

// Sampler is a sampler module, will sample the input at specified sample rate
type Sampler struct {
	sampledData []int
	// Sampled data.

	nextSampleIndex int
	// The next index in sampledData that we are going to write to in next sample

	sampleRate float64
	// Sample rate in Hz

	sim *Simulator
	// The Simulator
}

// NewSampler will create a new sampler module with the specified sample rate
func NewSampler(s *Simulator, sampleRate float64) *Sampler {
	return &Sampler{
		sim:             s,
		sampleRate:      sampleRate,
		nextSampleIndex: 0,
		sampledData:     make([]int, int(s.simulationTime*sampleRate)+32),
	}
}

func (s *Sampler) step(val int) {
	if float64(s.nextSampleIndex)*(1.0/s.sampleRate) < s.sim.currentTime {
		// Do sample
		s.sampledData[s.nextSampleIndex] = val
		s.nextSampleIndex++
	}
}

// IOTProtocolDecoder is an IOT Protocol Decoder module, will take an input bit stream, look for the IOT Protocol header byte, then decode it. After that, it'll call the packet handler, and let it choose to respond or not.
type IOTProtocolDecoder struct {
	sim *Simulator
	// The simulator

	packetHandler func(*IOTProtocolDecoder, []byte)
	// handler for packet

	tx *BitStreamTx
	// Transmitter for transmitting reply after receiving command

	sampler *Sampler
	// Sampler for sampling the incoming signal

	nextIndex int
	// Next index to process

	state int
	// 0 Scanning for start byte
	// 1 Found start byte, waiting for it to finish

	packetLength int
	// The length of the packet, only valid when state is 1

	decodeBufferBit []int
	// Buffer to hold the bits to decode

	decodeBuffer []byte
	// Buffer to hold the decoded byte

	crcTable *crc8.Table
	// CRC Table for calculating the CRC
}

// NewIOTProtocolDecoder will create a new IOT Protocol Decoder
func NewIOTProtocolDecoder(s *Simulator, tx *BitStreamTx, packetHandler func(*IOTProtocolDecoder, []byte)) *IOTProtocolDecoder {
	return &IOTProtocolDecoder{
		sampler:         NewSampler(s, IOTBaudRate*5.0), // We sample at 5x the baud rate, and pick only the center
		nextIndex:       0,
		state:           0,
		decodeBufferBit: make([]int, 8*260),
		decodeBuffer:    make([]byte, 260),
		crcTable:        crc8.MakeTable(Crc8Poly),
		tx:              tx,
		packetHandler:   packetHandler,
	}
}

func (d *IOTProtocolDecoder) doDecodeBuffer() {
	for i := 0; i < 260; i++ {
		b := 1  // Shifting bit
		cb := 0 // Current byte

		// LSB first
		for j := 0; j < 8; j++ {
			if d.decodeBufferBit[i*8+j] != 0 {
				cb = cb | b
			}
			b = b << 1
		}
		d.decodeBuffer[i] = byte(cb)
	}
}

func (d *IOTProtocolDecoder) step(in int) {
	if in != 0 {
		in = 1
	}

	d.sampler.step(in)

	// Pattern to match, -1 for Don't Care, 0 match 0, 1 match 1
	pattern := []int{
		// 8 Bits of 0x55, the header
		-1, 1, 1, 1, -1,
		-1, 0, 0, 0, -1,
		-1, 1, 1, 1, -1,
		-1, 0, 0, 0, -1,
		-1, 1, 1, 1, -1,
		-1, 0, 0, 0, -1,
		-1, 1, 1, 1, -1,
		-1, 0, 0, 0, -1,
	}

	if d.state == 0 {
		// Scan for the start byte

		// We only scan it when more than 5 bytes is available
		for d.sampler.nextSampleIndex > d.nextIndex+5*8*5 {
			found := true
			for i, current := range pattern {
				if current == -1 {
					continue
				}
				if current == 0 && d.sampler.sampledData[i+d.nextIndex] == 0 {
					continue
				}
				if current == 1 && d.sampler.sampledData[i+d.nextIndex] == 1 {
					continue
				}
				found = false
				break
			}

			if found {
				// Decode the first 3 bytes
				for i := 0; i <= 8*3; i++ {
					// Fetch the middle of each bit
					d.decodeBufferBit[i] = d.sampler.sampledData[d.nextIndex+2+i*5]
				}
				d.doDecodeBuffer()

				// Second byte is the length
				d.packetLength = int(d.decodeBuffer[1])

				d.state = 1
				break
			}

			d.nextIndex++
		}
	} else if d.state == 1 {
		// We are waiting for data
		if d.sampler.nextSampleIndex > d.nextIndex+5*8*d.packetLength {
			// Our packet have arrived
			for i := 0; i <= 8*d.packetLength; i++ {
				// Fetch the middle of each bit
				d.decodeBufferBit[i] = d.sampler.sampledData[d.nextIndex+2+i*5]
			}
			d.doDecodeBuffer()

			// Check if the packet is correct
			csum := crc8.Checksum(d.decodeBuffer[0:d.packetLength-1], d.crcTable)
			if csum == uint8(d.decodeBuffer[d.packetLength-1]) {
				// The packet is valid
				d.packetHandler(d, d.decodeBuffer[2:d.packetLength-1])
			}
			d.nextIndex = d.nextIndex + 5*8*d.packetLength
			d.state = 0
		}
	}
}

// NECDecoder is an NEC IR Protocol decoder
type NECDecoder struct {
	// We assume the default state is low, and will record all transition

	sim *Simulator
	// The simulator

	lastState int
	// Last value of the receiver

	pulseWidths []float64
	// Pulse width of the recorded pulse, even entries are low pulse, odd entries are high pulse

	lastTransition float64
	// The time of the last transition

	nextPulse int
	// Index of the slot that we are going to write into in pulseWidths when the next transition comes

	nextDecode int
	// The next index that we are going to start decoding from
}

// NewNECDecoder will create a new NEC IR Protocol decoder
func NewNECDecoder(s *Simulator) *NECDecoder {
	return &NECDecoder{
		sim:            s,
		lastState:      0,
		pulseWidths:    make([]float64, int(s.simulationTime*IOTBaudRate*2)+32),
		lastTransition: 0.0,
		nextPulse:      0,
		nextDecode:     1,
	}
}

func (d *NECDecoder) step(v int) {
	// Do pulse tracking first
	if v != d.lastState {
		// State is different, record the pulse width
		d.pulseWidths[d.nextPulse] = d.sim.currentTime - d.lastTransition
		d.lastTransition = d.sim.currentTime
		d.nextPulse++
	}
	d.lastState = v

	// There is a a total of 34 high pulse and 33 low pulse in each NEC Remote pulse train
	// The first one is always a high one, so we start decoding on the odd entries, and when there's 67 pulses available
	if d.nextPulse-d.nextDecode >= 67 {
		ok, _ := tryDecodeNEC(d.pulseWidths[d.nextDecode : d.nextDecode+67])
		if ok {
			d.sim.remoteButtonReceived = true
		} else {
		}
		d.nextDecode += 2
	}
}

func tryDecodeNEC(pw []float64) (bool, []byte) {
	resb := make([]int, 32)
	resbytes := make([]byte, 4)
	res := make([]byte, 2)

	fm := func(val float64, target float64, tolerance float64) bool {
		if val > target*tolerance {
			return false
		}
		if val < target/tolerance {
			return false
		}
		return true
	}

	fmHi := func(val float64) bool {
		// 560 us Mark time
		return fm(val, 560*1e-6, 1.25)
	}

	fmLo0 := fmHi
	fmLo1 := func(val float64) bool {
		// 1.69 ms Space time
		return fm(val, 1.69*1e-3, 1.25)
	}

	if !fm(pw[0], 9.0*1e-3, 1.10) {
		return false, res
	}

	if !fm(pw[1], 4.5*1e-3, 1.15) {
		return false, res
	}

	for i := 0; i < 32; i++ {
		if !fmHi(pw[2+i*2]) {
			return false, res
		}
		if fmLo0(pw[2+i*2+1]) {
			resb[i] = 0
		} else if fmLo1(pw[2+i*2+1]) {
			resb[i] = 1
		} else {
			return false, res
		}
	}

	for i := 0; i < 4; i++ {
		sb := 1 // Shifting bit
		cb := 0 // Current byte
		for j := 0; j < 8; j++ {
			if resb[i*8+j] == 1 {
				cb = cb | sb
			}
			sb = sb << 1
		}
		resbytes[i] = byte(cb)
	}
	if resbytes[0] != (resbytes[1] ^ 0xFF) {
		return false, res
	}
	if resbytes[2] != (resbytes[3] ^ 0xFF) {
		return false, res
	}
	res[0] = resbytes[0]
	res[1] = resbytes[2]
	return true, res
}

// Simulator is the root simulator module
type Simulator struct {
	sampleRate float64
	// Sample rate of the simulator
	// Usually runs at 150kHz

	inputData []int
	// A series of 0 and 1 to denote the content of the input bitstream
	// Input bitstream is clocked at 1.785kHz

	currentStep int
	// The current progress of the simulator. (What time is it in the simulation?)

	currentTime float64
	// Current time in the simulation

	maxStep int
	// Number of steps that we are going to run the simulation

	simulationTime float64
	// Total time that we are going to run the simulation, in seconds

	rand *rand.Rand
	// The random generator that generate the random state of this simulator

	tvRx *IRReceiver
	// IR Receiver for the TV

	tvDec *NECDecoder
	// NEC Decoder for the TV

	hubTx *IRTransmitter
	// IR Transmitter on Hub's side

	hubBSTx *BitStreamTx
	// Bitstream transmitter on Hub's side

	hubRx *IRReceiver
	// IR Receiver on the Hub

	hubDec *IOTProtocolDecoder
	// Protocol decoder on Hub's side

	iotTx *IRTransmitter
	// IR Transmitter on IOT Device side

	iotBSTx *BitStreamTx
	// Bitstream Transmitter on IOT Device side

	iotRx *IRReceiver
	// IR Receiver on the IOT Device

	iotDec *IOTProtocolDecoder
	// Protocol decoder on IOT Device side

	resultReply []byte
	// The resulting reply that we've received

	remoteButtonReceived bool
	// If we detected a button press

	// Debugging variables
	irL []float64 // IR Illuminance
}

// NewSimulator will create a new simulator module
func NewSimulator(simTime float64) *Simulator {
	x := Simulator{
		rand:                 rand.New(rand.NewSource(time.Now().Unix())),
		currentStep:          0,
		sampleRate:           DefaultSampleRate,
		simulationTime:       simTime,
		maxStep:              int(math.Floor(simTime * DefaultSampleRate)),
		resultReply:          []byte{},
		remoteButtonReceived: false,
	}

	x.irL = make([]float64, x.maxStep+32) // Yeah, I'm lazy on preventing off by one.

	hubHandlePacket := func(d *IOTProtocolDecoder, b []byte) {
		if b[0]&CommandReply != 0 {
			x.resultReply = b
		}
	}

	x.hubBSTx = NewBitStreamTx(&x)
	x.hubTx = NewIRTransmitter(&x)
	x.hubRx = NewIRReceiver(&x)
	x.hubDec = NewIOTProtocolDecoder(&x, x.hubBSTx, hubHandlePacket)

	x.iotTx = NewIRTransmitter(&x)
	x.iotBSTx = NewBitStreamTx(&x)
	x.iotRx = NewIRReceiver(&x)
	x.iotDec = NewIOTProtocolDecoder(&x, x.iotBSTx, iotHandlePacket)

	x.tvRx = NewIRReceiver(&x)
	x.tvDec = NewNECDecoder(&x)

	return &x
}

func iotHandlePacket(d *IOTProtocolDecoder, packet []byte) {
	// Handles packet on the IOT Device side
	if packet[0] == CommandPing {
		// Take whatever we receive and send it back
		reply := make([]byte, len(packet))
		copy(reply[1:], packet[1:])
		reply[0] = CommandReply | CommandPing
		for i := 0; i < len(packet)-1; i++ {
			// Some bit manipulation for sanity check
			reply[i+1] = reply[i+1] ^ byte((0x12+i)&0xFF)
		}
		d.tx.appendPacket(reply)
	}

	if packet[0] == CommandGetTemp {
		// 27.2 degree C is expressed as 272 = 0x01 0x10 (Big Endian)
		reply := []byte{packet[0] | CommandReply, 0x01, 0x10}
		d.tx.appendPacket(reply)
	}

	if packet[0] == CommandGetHumidity {
		// 72.1% humidity is expressed as 721 = 0x02 0xD1
		reply := []byte{packet[0] | CommandReply, 0x02, 0xD1}
		d.tx.appendPacket(reply)
	}

	if packet[0] == CommandGetCO2 {
		// 422ppm => 422 = 0x01 0xA6
		reply := []byte{packet[0] | CommandReply, 0x01, 0xA6}
		d.tx.appendPacket(reply)
	}

	if packet[0] == CommandGetSmokeDetector {
		// No smoke detected = 0
		reply := []byte{packet[0] | CommandReply, 0x00}
		d.tx.appendPacket(reply)
	}

	if packet[0] == CommandSetTime {
		// <Year 2 Byte> <Month 1 Byte> <Day 1 Byte> <Hour 1 Byte> <Minute 1 Byte> <Second 1 Byte>
		ok := true
		if len(packet) == 8 {
			if int(packet[3]) > 12 || int(packet[3]) < 1 {
				ok = false
			}
			if int(packet[4]) > 31 || int(packet[4]) < 1 {
				ok = false
			}
			if int(packet[5]) > 24 {
				ok = false
			}
			if int(packet[6]) > 60 {
				ok = false
			}
			if int(packet[7]) > 60 {
				ok = false
			}
		} else {
			ok = false
		}
		reply := []byte{packet[0] | CommandReply, 0x00}
		if ok {
			reply[1] = 0x01
		}
		d.tx.appendPacket(reply)
	}

	if packet[0] == CommandSystemVersion {
		// Ver 3.14
		reply := []byte{packet[0] | CommandReply, 0x03, 0x0E}
		d.tx.appendPacket(reply)
	}
}

func (s *Simulator) step() {
	// Get current time
	cT := float64(s.currentStep) / s.sampleRate
	s.currentTime = cT
	irL := 5.0e-9 + s.rand.Float64()*(1.0e-9) // Amount of light in the room, plus some background noise

	// Hub's IR Transmission
	// Get the logic output at the hub's IR transmitter GPIO for this step
	hubIRGpio := s.hubBSTx.step()
	// Modulate the carrier and at 3.3V
	hubIRGpioV := s.hubTx.step(float64(hubIRGpio) * 3.3)
	// IR LED have a frequency response of > 1MHz, so we'll not simulate its frequency response
	irL = math.Max(irL, hubIRGpioV/3.3) // Add the light from the emitter

	// Device's IR Transmission
	// Get the logic output at the hub's IR transmitter GPIO for this step
	IotIRGpio := s.iotBSTx.step()
	// Modulate the carrier and at 3.3V
	IotIRGpioV := s.iotTx.step(float64(IotIRGpio) * 3.3)
	// IR LED have a frequency response of > 1MHz, so we'll not simulate its frequency response
	irL = math.Max(irL, IotIRGpioV/3.3) // Add the light from the emitter

	s.irL[s.currentStep] = irL

	iotRxV := s.iotRx.step(irL)
	s.iotDec.step(iotRxV)

	hubRxV := s.hubRx.step(irL)
	s.hubDec.step(hubRxV)

	tvRxV := s.tvRx.step(irL)
	s.tvDec.step(tvRxV)

	// Increase the current time
	s.currentStep++
}

func (s *Simulator) runSim() {
	for i := 0; i < s.maxStep; i++ {
		s.step()
	}
}
