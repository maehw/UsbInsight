# UsbInsight
# Copyright (C) 2024 maehw
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Note: Please check the accompanying README.md file for functional limitations.

import os
import argparse
import pandas as pd
import copy


# Generic finite state model class used for parsing USB packets and transactions
class UsbFsm:
    def __init__(self, initial_state):
        self.state = initial_state
        self.transitions = {}

    def add_transition(self, from_state, to_state, condition):
        if from_state not in self.transitions:
            self.transitions[from_state] = []
        self.transitions[from_state].append((condition, to_state))

    def run(self, input_value):
        if self.state in self.transitions:
            for condition, to_state in self.transitions[self.state]:
                if condition(input_value):
                    self.state = to_state
                    return self.state
        return self.state


class UsbPacket:
    def __init__(self, start_time_us, pid):
        self.start_time_us = start_time_us
        self.end_time_us = None
        self.pid = pid
        self.addr = None
        self.ep = None
        self.data = None

    def set_end_time(self, end_time_us):
        self.end_time_us = end_time_us

    def __repr__(self):
        return f"UsbPacket(PID: {self.pid})"

    def data_repr(self, show_decimal=False, ascii_characters=False):
        if ascii_characters:
            c = get_ascii_repr(self.data, show_decimal)
            if c is not None:
                return c
        if show_decimal:
            return f"{self.data}"
        else:
            return declist2hexstr(self.data)

    def to_csv(self, show_decimal=False, ascii_characters=False):
        addr = ''
        if self.addr is not None:  # zeroes are also falsy
            addr = self.addr
        ep = ''
        if self.ep is not None:  # zeroes are also falsy
            ep = self.ep
        data = ''
        if self.data == [] or self.data:  # also show empty lists, only hide None
            data = self.data_repr(show_decimal, ascii_characters)
        return f"{self.start_time_us};{self.end_time_us};{self.pid};{addr};{ep};{data}"


class UsbSofPacket(UsbPacket):
    def __init__(self, start_time_us):
        super().__init__(start_time_us, 'SOF')
        self.frame_number = None

    def set_frame_number(self, frame_number):
        self.frame_number = frame_number

    def __repr__(self):
        return f"UsbSofPacket(FrameNumber: {self.frame_number})"


class UsbTokenPacket(UsbPacket):
    def __init__(self, start_time_us, pid):
        super().__init__(start_time_us, pid)
        self.addr = None
        self.ep = None

    def set_addr_ep(self, addr, ep):
        self.addr = addr
        self.ep = ep

    def __repr__(self):
        return f"UsbTokenPacket(PID: {self.pid}, Addr.: {self.addr}, EP: {self.ep})"


class UsbDataPacket(UsbPacket):
    def __init__(self, start_time_us, pid):
        super().__init__(start_time_us, pid)
        self.data = []

    def append(self, data):
        self.data.append(data)

    def __repr__(self):
        return f"UsbDataPacket(PID: {self.pid}, data: {super().data_repr()})"


class UsbHandshakePacket(UsbPacket):
    def __init__(self, start_time_us, pid):
        super().__init__(start_time_us, pid)

    def __repr__(self):
        return f"UsbHandshakePacket(PID: {self.pid})"


class UsbTransaction:
    def __init__(self, start_time_us, transaction_type, addr, ep):
        self.start_time_us = start_time_us
        self.end_time_us = None
        self.type = transaction_type
        self.addr = addr
        self.ep = ep
        self.data = []
        self.success = None

    def get_ep(self):
        return self.ep

    def get_address(self):
        return self.addr

    def get_type(self):
        return self.type

    def get_data_len(self):
        return len(self.data)

    def get_data_as_bytearray(self):
        return bytearray(self.data)

    def get_start_time(self):
        return self.start_time_us

    def is_successful(self):
        return self.success

    def set_data(self, data):
        self.data = data

    def finish(self, success, end_time_us):
        self.success = success
        self.end_time_us = end_time_us

    def data_repr(self, show_decimal=False, ascii_characters=False):
        if self.type == 'SETUP':
            if not self.data:
                return "?"
            else:
                assert len(self.data) == 8, 'Setup packet expected to be 8 bytes long'
                request_type = self.data[0]
                request = self.data[1]
                return (
                    f"bmRequestType={get_request_type_descr(request_type)}, "
                    f"bRequest={get_standard_request_name(request, request_type)}, "
                    f"wValue=0x{list_to_uint16(self.data[2:4]):04X}, "
                    f"wIndex=0x{list_to_uint16(self.data[4:6]):04X}, "
                    f"wLength=0x{list_to_uint16(self.data[6:]):04X}")
        else:
            if ascii_characters:
                c = get_ascii_repr(self.data)
                if c is not None:
                    return c
            if show_decimal:
                return f"{self.data}"
            else:
                return declist2hexstr(self.data)

    def __repr__(self):
        end_time = "End: ?, "
        if self.end_time_us is not None:  # zeroes are also falsy
            end_time = f"End: {self.end_time_us/1e6:.06f}s, "

        return (f"UsbTransaction("
                f"Start: {self.start_time_us/1e6:.06f}s, "
                f"{end_time}"
                f"Type: {self.type}, "
                f"Addr.: {self.addr}, "
                f"EP: {self.ep}, "
                f"Success: {self.success}, "
                f"Data: {self.data_repr()})")

    def to_csv(self, show_success_column=False, show_decimal=False, ascii_characters=False):
        s = ''
        if show_success_column:
            s = f";{self.success}"
        return (f"{self.start_time_us};{self.end_time_us};{self.type};{self.addr};{self.ep};"
                f"{self.data_repr(show_decimal, ascii_characters)}{s}")


def list_to_uint16(data):
    assert len(data) == 2
    return int.from_bytes(data, byteorder='little')


def get_ascii_repr(value, show_decimal=False):
    if isinstance(value, list):
        return [get_ascii_repr(v) for v in value]
    else:
        # check if the value is a valid ASCII code
        if 0 <= value <= 127:
            char = chr(value)
            # check if the character is printable but also
            # NOT a specific whitespace (tab, line break, carriage return)
            # and also not a comma, nor a semicolon, nor single tick or double quotes
            # to prevent breaking the CSV file
            if char.isprintable() and (value not in [9, 10, 13, 34, 39, 44, 59]):
                return char
        if show_decimal:
            return value
        else:
            # treat first part as a raw string for proper handling of the backslash
            return r"\x" + f"{value:02X}"  # FIXME: still printed as two backslashes; how to properly (not?) escape


def get_request_type_descr(request_type):
    descr = f"0x{request_type:02X}=" + r"{dir="

    if request_type & (1 << 7):
        descr += "host<-dev"
    else:
        descr += "host->dev"

    descr += ", type="
    tp = (request_type >> 5) & 0x3
    tp_descr = {0: 'standard', 1: 'class', 2: 'vendor', 3: 'reserved'}
    descr += tp_descr[tp]

    descr += ", rcpt="
    rcpt = request_type & 0x1F
    rcpt_descr = {0: 'device', 1: 'interface', 2: 'endpoint', 3: 'other'}
    if rcpt in rcpt_descr:
        descr += rcpt_descr[rcpt]
    else:
        descr += "reserved"

    descr += r"}"
    return descr


def get_standard_request_name(request_id, request_type):
    # get name of the standard request if it is one; otherwise return the hex value
    #
    # standard requests according to https://www.usbmadesimple.co.uk/ums_4.htm +
    # https://www.beyondlogic.org/usbnutshell/usb6.shtml;
    # in numerical, ascending order of the request ID
    name = f"0x{request_id:02X}"  # always start with hex representation
    if request_id == 0x00:
        # data phase transfer direction: always device to host
        # recipient: device, interface or endpoint
        if request_type in [0x80, 0x81, 0x82]:
            name += '=GET_STATUS'
    elif request_id == 0x01:
        # data phase transfer direction: always host to device
        # recipient: device, interface or endpoint
        if request_type in [0x00, 0x01, 0x02]:
            name += '=CLEAR_FEATURE'
    elif request_id == 0x03:
        # data phase transfer direction: always host to device
        # recipient: device, interface or endpoint
        if request_type in [0x00, 0x01, 0x02]:
            name += '=SET_FEATURE'
    elif request_id == 0x05:
        # data phase transfer direction: host to device
        # recipient: device
        if request_type == 0x00:
            name += '=SET_ADDRESS'
    elif request_id == 0x06:
        # data phase transfer direction: device to host
        # recipient: device
        if request_type == 0x80:
            name += '=GET_DESCRIPTOR'
    elif request_id == 0x07:
        # data phase transfer direction: host to device
        # recipient: device
        if request_type == 0x00:
            name += '=SET_DESCRIPTOR'
    elif request_id == 0x08:
        # data phase transfer direction: device to host
        # recipient: device
        if request_type == 0x80:
            name += '=GET_CONFIGURATION'
    elif request_id == 0x09:
        # data phase transfer direction: host to device
        # recipient: device
        if request_type == 0x00:
            name += '=SET_CONFIGURATION'
    elif request_id == 0x0A:
        # data phase transfer direction: device to host
        # recipient: interface
        if request_type == 0x81:
            name += '=GET_INTERFACE'
    elif request_id == 0x11:
        # data phase transfer direction: host to device
        # recipient: interface
        if request_type == 0x01:
            name += '=SET_INTERFACE'
    elif request_id == 0x12:
        # data phase transfer direction: device to host
        # recipient: endpoint
        if request_type == 0x82:
            name += '=SYNCH_FRAME'
    return name


# Conditions
def is_sync(field):
    return field == 'SYNC'


def is_pid_sof(field):
    return field == 'PID SOF'


def is_pid_token(field):
    return field in ['PID SETUP', 'PID IN', 'PID OUT']


def get_pid(field):
    return field[4:]


def is_pid_data(field):
    return ('PID DATA' in field) or ('PID MDATA' in field)


def is_pid_handshake(field):
    assert field != 'PID NYET'  # FIXME: haven't ever seen 'NYET' handshake packets, currently cannot handle them
    return field in ['PID ACK', 'PID NAK', 'PID STALL']


def is_data(field):
    return 'Byte 0x' in field


def is_crc(field):
    return field == 'CRC'


def is_eop(field):
    return field == 'EOP'


def is_addr_ep(field):
    return ('Address=0x' in field) and ('Endpoint=0x' in field)


def get_addr_ep(field):
    return field[10:13], field[24:]


def is_crc_ok(field):
    return 'CRC OK' in field


def get_data_byte(field):
    if 'Byte ' in field:
        return field[7:9]
    else:
        return None


def is_frame_no(field):
    return field.startswith('Frame # 0x')


def get_frame_number(field):
    if not is_frame_no(field):
        return None
    else:
        return int(field[10:], 16)


def is_in_packet(packet):
    return packet.pid == 'IN'


def is_out_packet(packet):
    return packet.pid == 'OUT'


def is_setup_packet(packet):
    return packet.pid == 'SETUP'


def is_data_packet(packet):
    return 'DATA' in packet.pid


def is_ack_packet(packet):
    return packet.pid == 'ACK'


def is_nak_packet(packet):
    return packet.pid == 'NAK'


def is_setup_transaction(transaction):
    return transaction.get_type() == 'SETUP'


def is_zerolength_inout_transaction(transaction):
    return transaction.get_data_len() == 0 and transaction.get_type() in ['IN', 'OUT']


def is_nonempty_in_transaction(transaction):
    return transaction.get_data_len() != 0 and is_in_transaction(transaction)


def is_in_transaction(transaction):
    return transaction.get_type() == 'IN'


def is_zerolength_out_transaction(transaction):
    return transaction.get_data_len() == 0 and is_out_transaction(transaction)


def is_nonempty_out_transaction(transaction):
    return transaction.get_data_len() != 0 and is_out_transaction(transaction)


def is_out_transaction(transaction):
    return transaction.get_type() == 'OUT'


def is_zerolength_in_transaction(transaction):
    return transaction.get_data_len() == 0 and is_in_transaction(transaction)


def declist2hexstr(list_object):
    assert isinstance(list_object, list)
    return '[' + ', '.join(["0x{:02X}".format(e) for e in list_object]) + ']'


# Collect packets and transactions
packets = []
transactions = []

# Initialize FSM for USB packets
pfsm = UsbFsm('IDLE')

# Add transitions
pfsm.add_transition('IDLE', 'SYNC', is_sync)  # this is the only transition out of IDLE

# start of frame (SOF) packet
pfsm.add_transition('SYNC', 'SOF_PID', is_pid_sof)
pfsm.add_transition('SOF_PID', 'SOF_FRAME_NO', is_frame_no)
pfsm.add_transition('SOF_FRAME_NO', 'SOF_CRC_OK', is_crc_ok)
pfsm.add_transition('SOF_CRC_OK', 'SOF_CPLT', is_eop)
pfsm.add_transition('SOF_CPLT', 'IDLE', lambda field: True)  # return to IDLE after virtual state

# token packet
pfsm.add_transition('SYNC', 'TOKEN_PID', is_pid_token)
pfsm.add_transition('TOKEN_PID', 'TOKEN_ADDR_EP', is_addr_ep)
pfsm.add_transition('TOKEN_ADDR_EP', 'TOKEN_CRC_OK', is_crc_ok)
pfsm.add_transition('TOKEN_CRC_OK', 'TOKEN_CPLT', is_eop)
pfsm.add_transition('TOKEN_CPLT', 'IDLE', lambda field: True)  # return to IDLE after virtual state

# data packet
pfsm.add_transition('SYNC', 'DATA_PID', is_pid_data)
pfsm.add_transition('DATA_PID', 'DATA_PAYLOAD', is_data)
pfsm.add_transition('DATA_PAYLOAD', 'DATA_PAYLOAD', is_data)
pfsm.add_transition('DATA_PID', 'DATA_CRC_OK', is_crc_ok)
pfsm.add_transition('DATA_PAYLOAD', 'DATA_CRC_OK', is_crc_ok)
pfsm.add_transition('DATA_CRC_OK', 'DATA_CPLT', is_eop)
pfsm.add_transition('DATA_CPLT', 'IDLE', lambda field: True)  # return to IDLE after virtual state

# handshake packet
pfsm.add_transition('SYNC', 'HANDSHAKE_PID', is_pid_handshake)
pfsm.add_transition('HANDSHAKE_PID', 'HANDSHAKE_CPLT', is_eop)
pfsm.add_transition('HANDSHAKE_CPLT', 'IDLE', lambda field: True)  # return to IDLE after virtual state

# TODO: add bad case transitions; add them after all other transitions!
# return to IDLE after a decoding error has occurred
pfsm.add_transition('SYNC', 'IDLE', lambda field: True)  # unhandled PID (e.g. 'NYET' is not handled yet)
pfsm.add_transition('TOKEN_PID', 'IDLE', lambda field: True)  # no address + endpoint fields
pfsm.add_transition('TOKEN_ADDR_EP', 'IDLE', lambda field: True)  # invalid CRC
pfsm.add_transition('TOKEN_CRC_OK', 'IDLE', lambda field: True)  # missing EOP

# Initialize FSM for USB transactions
tfsm = UsbFsm('IDLE')

# Add transitions
tfsm.add_transition('IDLE', 'READ', is_in_packet)
tfsm.add_transition('IDLE', 'WRITE', is_out_packet)
tfsm.add_transition('IDLE', 'CTRL', is_setup_packet)

tfsm.add_transition('READ', 'READ_BUSY', is_nak_packet)
tfsm.add_transition('READ_BUSY', 'IDLE', lambda field: True)  # return to IDLE after virtual state
tfsm.add_transition('READ', 'READ_PAYLOAD', is_data_packet)
tfsm.add_transition('READ_PAYLOAD', 'READ_CPLT', is_ack_packet)
tfsm.add_transition('READ_PAYLOAD', 'READ_FAILED', is_nak_packet)
tfsm.add_transition('READ_CPLT', 'IDLE', lambda field: True)  # return to IDLE after virtual state
tfsm.add_transition('READ_FAILED', 'IDLE', lambda field: True)  # return to IDLE after virtual state

tfsm.add_transition('WRITE', 'WRITE_PAYLOAD', is_data_packet)
tfsm.add_transition('WRITE_PAYLOAD', 'WRITE_CPLT', is_ack_packet)
tfsm.add_transition('WRITE_PAYLOAD', 'WRITE_FAILED', is_nak_packet)
tfsm.add_transition('WRITE_CPLT', 'IDLE', lambda field: True)  # return to IDLE after virtual state
tfsm.add_transition('WRITE_FAILED', 'IDLE', lambda field: True)  # return to IDLE after virtual state

tfsm.add_transition('CTRL', 'CTRL_PAYLOAD', is_data_packet)
tfsm.add_transition('CTRL_PAYLOAD', 'CTRL_CPLT', is_ack_packet)
tfsm.add_transition('CTRL_CPLT', 'IDLE', lambda field: True)  # return to IDLE after virtual state


# Initialize FSM for USB control transfers
ctrlpipe_fsm = UsbFsm('IDLE')

# Add transitions
ctrlpipe_fsm.add_transition('IDLE', 'SETUP', is_setup_transaction)

ctrlpipe_fsm.add_transition('SETUP', 'IDLE', is_zerolength_inout_transaction)

ctrlpipe_fsm.add_transition('SETUP', 'IN_TRANSFER', is_nonempty_in_transaction)
ctrlpipe_fsm.add_transition('IN_TRANSFER', 'IN_TRANSFER', is_in_transaction)
ctrlpipe_fsm.add_transition('IN_TRANSFER', 'IN_TRANSFER_CPLT', is_zerolength_out_transaction)
ctrlpipe_fsm.add_transition('IN_TRANSFER_CPLT', 'IDLE', lambda field: True)  # return to IDLE after virtual state

ctrlpipe_fsm.add_transition('SETUP', 'OUT_TRANSFER', is_nonempty_out_transaction)
ctrlpipe_fsm.add_transition('OUT_TRANSFER', 'OUT_TRANSFER', is_out_transaction)
ctrlpipe_fsm.add_transition('OUT_TRANSFER', 'OUT_TRANSFER_CPLT', is_zerolength_in_transaction)
ctrlpipe_fsm.add_transition('OUT_TRANSFER_CPLT', 'IDLE', lambda field: True)  # return to IDLE after virtual state


# initialize an empty dictionary which keeps data for handling control pipes (for individual USB addresses)
ctrlpipes = {}
# initialize an empty dictionary which keeps data for handling read/write pipes (for individual USB addresses)
rwpipes = {}


def process_control_pipe_transaction(t, export):
    # basically need to process control transfers here, i.e. check for its stages (setup, data, status);
    # this needs to be distinguished for every device (with its own address);
    # the binary data we're interested in is contained in the (optional(!)) data stage!
    #
    # after the setup stage,
    # check if there's a non-zero sized data stage;
    # - if this is the case, another zero-sized status stage is expected
    # - otherwise, the data stage has been omitted and there's nothing to export anyway
    #
    # return the USB device address if this call completes a successful control transfer
    address_of_complete_ctl_xfer = None

    if t.is_successful():
        addr = t.get_address()
        ep = t.get_ep()
        assert ep == 0
        # check if we've already handled control pipes for this address before;
        # if not, initialize the required data structures
        if addr not in ctrlpipes:
            ctrlpipes[addr] = {'fsm': None, 'start_time': None, 'dir': None, 'data': bytearray()}
            # create own copy of the control transfer FSM for this USB address
            ctrlpipes[addr]['fsm'] = copy.deepcopy(ctrlpipe_fsm)

        # Run control transfer FSM
        state = ctrlpipes[addr]['fsm'].run(t)
        # print(state)  # only for debugging; could be used in some verbosity level

        if state == 'IDLE':
            ctrlpipes[addr]['data'] = bytearray()
        elif state == 'SETUP':
            ctrlpipes[addr]['data'] = bytearray()
            ctrlpipes[addr]['start_time'] = t.get_start_time()
        elif '_TRANSFER' in state:
            if 'IN_' in state:
                ctrlpipes[addr]['dir'] = 'IN'
            elif 'OUT_' in state:
                ctrlpipes[addr]['dir'] = 'OUT'
            ctrlpipes[addr]['data'].extend(t.get_data_as_bytearray())

        if '_CPLT' in state:
            address_of_complete_ctl_xfer = addr

            # store control transfer as file
            if export:
                directory = ctrlpipes[addr]['dir']
                binary_filename = f"{ctrlpipes[addr]['start_time']:09}_addr{addr}_ep0_{directory}.bin"
                with open(binary_filename, "wb") as f:
                    f.write(ctrlpipes[addr]['data'])

            state = ctrlpipes[addr]['fsm'].run('')
            # print(state)  # only for debugging; could be used in some verbosity level

    return address_of_complete_ctl_xfer


def process_rw_pipe_transaction(t):
    if t.is_successful():
        addr = t.get_address()
        ep = t.get_ep()
        assert ep != 0
        # check if we've already handled read/write pipes for this address before;
        # if not, initialize the required data structures
        if addr not in rwpipes:
            rwpipes[addr] = {}
        if ep not in rwpipes[addr]:
            rwpipes[addr][ep] = {'start_time': t.get_start_time(), 'dir': None, 'data': bytearray()}

        rwpipes[addr][ep]['dir'] = t.get_type()
        rwpipes[addr][ep]['data'].extend(t.get_data_as_bytearray())


def decode_usb(command_line_args):
    verbosity = command_line_args.verbose
    input_filename = command_line_args.input_filename
    output_filename = command_line_args.output_filename
    export_packets = command_line_args.packets
    export_transactions = command_line_args.transactions or command_line_args.all_transactions
    export_all_transactions = command_line_args.all_transactions
    export_control_pipes = command_line_args.extract_control
    export_rw_pipes = command_line_args.extract_data
    export_rw_pipes_parts = command_line_args.extract_parts
    decimal_not_hex = command_line_args.decimal
    ascii_characters = command_line_args.ascii_characters
    progress_bar = command_line_args.progress_bar

    if verbosity > 0:
        print(f"Verbosity: {verbosity}")
        print(f"Exporting packets: {export_packets}")
        print(f"Exporting transactions: {export_transactions}")
        print(f"Exporting all transactions: {export_all_transactions}")
        print(f"Exporting binary data from control transfers on endpoints 0 (control pipes): {export_control_pipes}")
        print(f"Exporting binary data from non-zero endpoints (read/write pipes): {export_rw_pipes}")
        if export_rw_pipes_parts:
            print(f"Exporting binary data from non-zero endpoints (read/write pipes) as parts.")
        print(f"Display progress bar: {progress_bar}")
        if decimal_not_hex:
            print("Using decimal", end="")
        else:
            print("Using hexadecimal", end="")
        print(f"Using printable ASCII characters: {ascii_characters}")
        print(" payload data representation in CSV output file")
        print("Decoding started.")

    # Load CSV file and parse it using pandas
    df = pd.read_csv(input_filename)

    # Check if the expected columns match (don't need more and also don't like less)
    assert df.columns.values.tolist() == ['name', 'type', 'start_time', 'duration', 'value'], 'Unexpected column format'

    packet = None
    transaction = None
    last_sync_us = None  # last SYNC start in microseconds

    # introduce a progress bar which is output to stderr
    pbar = None
    if progress_bar:
        from tqdm import tqdm
        pbar = tqdm(desc='Processed CSV lines', unit='line', unit_scale=True, total=len(df.index))

    for index, row in df.iterrows():
        # check assumptions for every row and "field"
        assert row['name'] == 'USB LS and FS', 'Unexpected name entry'
        assert row['type'] == 'v1frame', 'Unexpected type entry'
        field = row['value']
        assert field not in ['SE0', 'SE1', 'J', 'K'], 'Wrong USB analyzer decode level (too low)'
        assert 'bmRequestType=' not in field, 'Wrong USB analyzer decode level (too high)'
        assert 'bRequest=' not in field, 'Wrong USB analyzer decode level (too high)'
        assert 'wValue=' not in field, 'Wrong USB analyzer decode level (too high)'
        assert 'wIndex=' not in field, 'Wrong USB analyzer decode level (too high)'
        assert 'wLength=' not in field, 'Wrong USB analyzer decode level (too high)'

        # Run packet FSM
        state = pfsm.run(field)

        if ((not export_transactions) and (verbosity > 1)) or (export_transactions and (verbosity > 2)):
            print(f"[PACKET FIELD] {field}")  # note: could also output packet FSM state

        # Extract state relevant data and add it to the current packet
        if state == 'SYNC':
            last_sync_us = round(float(row['start_time'])*1e6)  # store time reference
        elif state == 'TOKEN_PID':
            packet = UsbTokenPacket(last_sync_us, get_pid(field))
        elif state == 'TOKEN_ADDR_EP':
            addr_str, ep_str = get_addr_ep(field)
            addr = int(addr_str, 16)
            ep = int(ep_str, 16)
            packet.set_addr_ep(addr, ep)
        elif state == 'DATA_PID':
            packet = UsbDataPacket(last_sync_us, get_pid(field))
        elif state == 'DATA_PAYLOAD':
            d = int(get_data_byte(field), 16)
            packet.append(d)
        elif state == 'HANDSHAKE_PID':
            packet = UsbHandshakePacket(last_sync_us, get_pid(field))
        elif state == 'SOF_PID':
            packet = UsbSofPacket(last_sync_us)
        elif state == 'SOF_FRAME_NO':
            packet.set_frame_number(get_frame_number(field))

        # Packet complete, auto-run virtual states to IDLE
        if '_CPLT' in state:
            end_time_us = round(float(row['start_time'])*1e6 + float(row['duration'])*1e6)
            packet.set_end_time(end_time_us)

            if ((not export_transactions) and (verbosity > 0)) or (export_transactions and (verbosity > 1)):
                print(f"[PACKET      ] {packet}")

            packets.append(packet)

            # only process transactions when they are exported (this will speed up processing)
            if export_transactions:
                # As we've got a packet now, run the transaction FSM
                tstate = tfsm.run(packet)

                if tstate in ['READ', 'WRITE', 'CTRL']:
                    transaction = UsbTransaction(packet.start_time_us, packet.pid, packet.addr, packet.ep)

                    if export_transactions and (verbosity > 1):
                        print(f"[TRANSACTION ] Starting transaction: {transaction}")
                elif '_PAYLOAD' in tstate:
                    transaction.set_data(packet.data)
                if ('_CPLT' in tstate) or ('_FAILED' in tstate) or ('_BUSY' in tstate):
                    if '_CPLT' in tstate:
                        transaction.finish(True, packet.end_time_us)
                    else:
                        transaction.finish(False, packet.end_time_us)

                # Transaction complete, auto-run virtual states to IDLE
                if ('_CPLT' in tstate) or ('_FAILED' in tstate) or ('_BUSY' in tstate):
                    if verbosity > 0:
                        print(f"[TRANSACTION ] Transaction: {transaction}")  # note: could output tstate here as well
                    transactions.append(transaction)

                    tstate = tfsm.run('')
                    assert tstate == 'IDLE', 'Expected auto transition to IDLE'

            packet = None  # reset
            state = pfsm.run('')

            # if verbosity > 0:  # note: could output USB packet state after having run packet fsm
            #    print(f"--> {state}")
            assert state == 'IDLE', 'Expected auto transition to IDLE'

        if pbar:
            pbar.update(1)

    if verbosity > 0:
        print("Decoding finished.")
        print()
        print("Summary:")
        print(f"{len(packets)} valid packets collected.")
        if export_transactions:
            print(f"{len(transactions)} transactions collected.")
        print()

    with open(output_filename, "w") as f:
        if export_packets:
            if verbosity > 0:
                print("Writing USB packet output data...")

            heading = "start_time_us;end_time_us;type;addr;ep;data"
            f.write(heading + os.linesep)

            for p in packets:
                csv_line = p.to_csv(decimal_not_hex, ascii_characters)
                f.write(csv_line + os.linesep)

        if export_transactions:
            if verbosity > 0:
                print("Writing USB transaction output data...")

            heading = "start_time_us;end_time_us;type;addr;ep;data"
            if export_all_transactions:
                heading += ";success"
            f.write(heading + os.linesep)

            for t in transactions:
                if t.success:
                    csv_line = t.to_csv(export_all_transactions, decimal_not_hex, ascii_characters)
                    f.write(csv_line + os.linesep)
                elif (not t.success) and export_all_transactions:
                    csv_line = t.to_csv(export_all_transactions, decimal_not_hex, ascii_characters)
                    f.write(csv_line + os.linesep)

    if export_control_pipes or export_rw_pipes:
        for t in transactions:
            ep = t.get_ep()
            if ep == 0:
                assert ep == 0
                # processing of control pipes is always active (as also required for R/W pipes);
                # only export (i.e. writing the output files) is optional
                address_of_complete_ctl_xfer = process_control_pipe_transaction(t, export_control_pipes)
                # as there may have been a control transfer, R/W pipe data can be split into parts
                if export_rw_pipes_parts and address_of_complete_ctl_xfer is not None:
                    # optionally flush read/write pipes here ("interrupted" by control transfers)
                    if address_of_complete_ctl_xfer in rwpipes.keys():
                        addr = address_of_complete_ctl_xfer
                        # side note: we must copy the dict keys here as we change the dict itself during iteration;
                        # (also: rwpipes is an empty dict if export_rw_pipes is False, no additional check required)
                        for flush_ep in list(rwpipes[addr].keys()):
                            # store read/write pipe data as file
                            direction = rwpipes[addr][flush_ep]['dir']
                            binary_filename = (f"{rwpipes[addr][flush_ep]['start_time']:09}_"
                                               f"addr{addr}_ep{flush_ep}_{direction}.bin")
                            with open(binary_filename, "wb") as f:
                                f.write(rwpipes[addr][flush_ep]['data'])
                            # reset data for this endpoint by deleting the dict entry
                            del rwpipes[addr][flush_ep]
            if ep != 0 and export_rw_pipes:
                assert ep != 0
                process_rw_pipe_transaction(t)
        # flush read/write pipes here
        # (rwpipes is an empty dict if export_rw_pipes is False, no additional check required)
        for addr in rwpipes.keys():
            for ep in rwpipes[addr].keys():
                # store read/write pipe data as file
                direction = rwpipes[addr][ep]['dir']
                binary_filename = f"{rwpipes[addr][ep]['start_time']:09}_addr{addr}_ep{ep}_{direction}.bin"
                with open(binary_filename, "wb") as f:
                    f.write(rwpipes[addr][ep]['data'])
        # TODO: think about if it also makes sense to "flush" pending data from incomplete control transfers


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='USB Protocol Decoder')
    parser.add_argument('-p',
                        '--packets',
                        action='store_true',
                        help='export valid decoded USB packets')
    parser.add_argument('-t',
                        '--transactions',
                        action='store_true',
                        help='export valid decoded USB transactions')
    parser.add_argument('-ta',
                        '--all-transactions',
                        action='store_true',
                        help='export all valid decoded transactions, not only the acknowledged ones')
    parser.add_argument('-d',
                        '--decimal',
                        action='store_true',
                        help='represent payload data as decimal values instead of hexadecimal in exported CSV file '
                             '(does not affect verbose output and fields of SETUP packet)')
    parser.add_argument('-c',
                        '--ascii-characters',
                        action='store_true',
                        help='represent payload data as ASCII printable characters in exported CSV file where feasible '
                             '(does not affect verbose output)')
    parser.add_argument('-xc',
                        '--extract-control',
                        action='store_true',
                        help='extract binary data from control transfers on endpoints 0 (control pipes) '
                             'as binary files (files are stored in current working directory)')
    parser.add_argument('-xd',
                        '--extract-data',
                        action='store_true',
                        help='extract binary data from non-zero endpoints (read/write pipes) '
                             'as binary files (files are stored in current working directory)')
    parser.add_argument('-xp',
                        '--extract-parts',
                        action='store_true',
                        help='split the extracted binary data from non-zero endpoints (read/write pipes) '
                             'into multiple binary files for every endpoint, split by every control transfer on the '
                             'same USB device address (endpoint 0)')
    parser.add_argument('-pbar',
                        '--progress-bar',
                        action='store_true',
                        help='show a progress bar on stderr')
    parser.add_argument('-v',
                        '--verbose',
                        action='count',
                        help='output more or less details on stdout, will slow things down; can add multiple, '
                             'e.g. -vvv',
                        default=0)
    parser.add_argument('input_filename',
                        type=str,
                        help='CSV input file containing USB packet field data')
    parser.add_argument('output_filename',
                        type=str,
                        help='CSV output file containing valid USB packet data or USB transaction data')

    args = parser.parse_args()

    # perform some checks on invalid command line argument combinations
    if (not args.packets) and (not args.transactions) and (not args.all_transactions):
        parser.print_help()
        parser.error('Need to provide either -p/--packets or -t/--transactions or -ta/--all-transactions')
    elif args.packets and (args.transactions or args.all_transactions):
        parser.print_help()
        parser.error('Cannot mix -p/--packets with -t/--transactions or -ta/--all-transactions')
    elif (args.extract_control or args.extract_data) and not (args.transactions or args.all_transactions):
        parser.print_help()
        parser.error('The use of -xc/--extract-control and -xd/--extract-data currently '
                     'also requires -t/--transactions or -ta/--all-transactions')
    elif args.extract_parts and not args.extract_data:
        parser.print_help()
        parser.error('The use of -xp/--extract-parts also requires -xd/--extract-data')
    else:
        decode_usb(args)
