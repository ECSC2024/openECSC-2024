#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Not titled yet
# GNU Radio version: 3.10.9.2

from gnuradio import analog
import math
from gnuradio import blocks
import pmt
from gnuradio import digital
from gnuradio import filter
from gnuradio.filter import firdes
from gnuradio import gr
from gnuradio.fft import window
import sys
import signal
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation




class fsk_modulator(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "Not titled yet", catch_exceptions=True)

        ##################################################
        # Variables
        ##################################################
        self.fsk_deviation = fsk_deviation = 170
        self.center_freq = center_freq = 2210
        self.space_freq = space_freq = center_freq - fsk_deviation/2
        self.mark_freq = mark_freq = center_freq + fsk_deviation/2
        self.full_scale_freq = full_scale_freq = 2500
        self.baud_rate = baud_rate = 100
        self.vco_offset = vco_offset = min(space_freq, mark_freq)/full_scale_freq
        self.samp_rate = samp_rate = 48000
        self.bit_time = bit_time = 1/baud_rate
        self.repeat_factor = repeat_factor = int(samp_rate*bit_time)
        self.inp_amp = inp_amp = (max(space_freq, mark_freq)/full_scale_freq)-vco_offset

        ##################################################
        # Blocks
        ##################################################

        self.freq_xlating_fir_filter_xxx_0 = filter.freq_xlating_fir_filter_fcf(1, firdes.low_pass(1.0,samp_rate,1000,400), center_freq, samp_rate)
        self.digital_binary_slicer_fb_0 = digital.binary_slicer_fb()
        self.blocks_vco_f_0 = blocks.vco_f(samp_rate, (2 * 3.141592653589793 * full_scale_freq), .5)
        self.blocks_uchar_to_float_0 = blocks.uchar_to_float()
        self.blocks_repeat_0 = blocks.repeat(gr.sizeof_char*1, repeat_factor)
        self.blocks_multiply_const_vxx_0 = blocks.multiply_const_ff(inp_amp)
        self.blocks_keep_one_in_n_0 = blocks.keep_one_in_n(gr.sizeof_char*1, repeat_factor)
        self.blocks_file_source_0 = blocks.file_source(gr.sizeof_char*1, 'C:\\Users\\GiovanniMinotti\\Downloads\\0x6DA1242199763B09.asc', True, 0, 0)
        self.blocks_file_source_0.set_begin_tag(pmt.PMT_NIL)
        self.blocks_file_sink_1 = blocks.file_sink(gr.sizeof_char*1, 'C:\\Users\\GiovanniMinotti\\Downloads\\dump.bin', False)
        self.blocks_file_sink_1.set_unbuffered(True)
        self.blocks_file_sink_0 = blocks.file_sink(gr.sizeof_float*1, 'C:\\Users\\GiovanniMinotti\\Downloads\\RF_48ksps_100bps.dat', False)
        self.blocks_file_sink_0.set_unbuffered(False)
        self.blocks_add_const_vxx_0 = blocks.add_const_ff(vco_offset)
        self.analog_quadrature_demod_cf_0 = analog.quadrature_demod_cf((samp_rate/(2*math.pi*fsk_deviation)))


        ##################################################
        # Connections
        ##################################################
        self.connect((self.analog_quadrature_demod_cf_0, 0), (self.digital_binary_slicer_fb_0, 0))
        self.connect((self.blocks_add_const_vxx_0, 0), (self.blocks_vco_f_0, 0))
        self.connect((self.blocks_file_source_0, 0), (self.blocks_repeat_0, 0))
        self.connect((self.blocks_keep_one_in_n_0, 0), (self.blocks_file_sink_1, 0))
        self.connect((self.blocks_multiply_const_vxx_0, 0), (self.blocks_add_const_vxx_0, 0))
        self.connect((self.blocks_repeat_0, 0), (self.blocks_uchar_to_float_0, 0))
        self.connect((self.blocks_uchar_to_float_0, 0), (self.blocks_multiply_const_vxx_0, 0))
        self.connect((self.blocks_vco_f_0, 0), (self.blocks_file_sink_0, 0))
        self.connect((self.blocks_vco_f_0, 0), (self.freq_xlating_fir_filter_xxx_0, 0))
        self.connect((self.digital_binary_slicer_fb_0, 0), (self.blocks_keep_one_in_n_0, 0))
        self.connect((self.freq_xlating_fir_filter_xxx_0, 0), (self.analog_quadrature_demod_cf_0, 0))


    def get_fsk_deviation(self):
        return self.fsk_deviation

    def set_fsk_deviation(self, fsk_deviation):
        self.fsk_deviation = fsk_deviation
        self.set_mark_freq(self.center_freq + self.fsk_deviation/2)
        self.set_space_freq(self.center_freq - self.fsk_deviation/2)
        self.analog_quadrature_demod_cf_0.set_gain((self.samp_rate/(2*math.pi*self.fsk_deviation)))

    def get_center_freq(self):
        return self.center_freq

    def set_center_freq(self, center_freq):
        self.center_freq = center_freq
        self.set_mark_freq(self.center_freq + self.fsk_deviation/2)
        self.set_space_freq(self.center_freq - self.fsk_deviation/2)
        self.freq_xlating_fir_filter_xxx_0.set_center_freq(self.center_freq)

    def get_space_freq(self):
        return self.space_freq

    def set_space_freq(self, space_freq):
        self.space_freq = space_freq
        self.set_inp_amp((max(self.space_freq, self.mark_freq)/self.full_scale_freq)-self.vco_offset)
        self.set_vco_offset(min(self.space_freq, self.mark_freq)/self.full_scale_freq)

    def get_mark_freq(self):
        return self.mark_freq

    def set_mark_freq(self, mark_freq):
        self.mark_freq = mark_freq
        self.set_inp_amp((max(self.space_freq, self.mark_freq)/self.full_scale_freq)-self.vco_offset)
        self.set_vco_offset(min(self.space_freq, self.mark_freq)/self.full_scale_freq)

    def get_full_scale_freq(self):
        return self.full_scale_freq

    def set_full_scale_freq(self, full_scale_freq):
        self.full_scale_freq = full_scale_freq
        self.set_inp_amp((max(self.space_freq, self.mark_freq)/self.full_scale_freq)-self.vco_offset)
        self.set_vco_offset(min(self.space_freq, self.mark_freq)/self.full_scale_freq)

    def get_baud_rate(self):
        return self.baud_rate

    def set_baud_rate(self, baud_rate):
        self.baud_rate = baud_rate
        self.set_bit_time(1/self.baud_rate)

    def get_vco_offset(self):
        return self.vco_offset

    def set_vco_offset(self, vco_offset):
        self.vco_offset = vco_offset
        self.set_inp_amp((max(self.space_freq, self.mark_freq)/self.full_scale_freq)-self.vco_offset)
        self.blocks_add_const_vxx_0.set_k(self.vco_offset)

    def get_samp_rate(self):
        return self.samp_rate

    def set_samp_rate(self, samp_rate):
        self.samp_rate = samp_rate
        self.set_repeat_factor(int(self.samp_rate*self.bit_time))
        self.analog_quadrature_demod_cf_0.set_gain((self.samp_rate/(2*math.pi*self.fsk_deviation)))
        self.freq_xlating_fir_filter_xxx_0.set_taps(firdes.low_pass(1.0,self.samp_rate,1000,400))

    def get_bit_time(self):
        return self.bit_time

    def set_bit_time(self, bit_time):
        self.bit_time = bit_time
        self.set_repeat_factor(int(self.samp_rate*self.bit_time))

    def get_repeat_factor(self):
        return self.repeat_factor

    def set_repeat_factor(self, repeat_factor):
        self.repeat_factor = repeat_factor
        self.blocks_keep_one_in_n_0.set_n(self.repeat_factor)
        self.blocks_repeat_0.set_interpolation(self.repeat_factor)

    def get_inp_amp(self):
        return self.inp_amp

    def set_inp_amp(self, inp_amp):
        self.inp_amp = inp_amp
        self.blocks_multiply_const_vxx_0.set_k(self.inp_amp)




def main(top_block_cls=fsk_modulator, options=None):
    tb = top_block_cls()

    def sig_handler(sig=None, frame=None):
        tb.stop()
        tb.wait()

        sys.exit(0)

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    tb.start()

    try:
        input('Press Enter to quit: ')
    except EOFError:
        pass
    tb.stop()
    tb.wait()


if __name__ == '__main__':
    main()
