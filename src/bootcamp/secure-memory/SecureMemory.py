from m5.objects.ClockedObject import ClockedObject
from m5.params import *


class SecureMemory(ClockedObject):
    type = "SecureMemory"
    cxx_header = "bootcamp/secure-memory/secure_memory.hh"
    cxx_class = "gem5::SecureMemory"

    cpu_side_port = ResponsePort(
        "ResponsePort to received requests from CPU side."
    )
    mem_side_port = RequestPort(
        "RequestPort to send received requests to memory side."
    )

    inspection_buffer_entries = Param.Int(
        "Number of entries in the inspection buffer."
    )

    insp_window = Param.Int(
        "Number of entries in front of inspectionBuffer "
        "to try to inspect every cycle."
    )
    num_insp_units = Param.Int("Number of inspection units.")
    insp_tot_latency = Param.Cycles(
        "Latency to complete one inspection (latency of an inspection unit)."
    )

    output_buffer_entries = Param.Int("Number of entries in output buffer.")

    response_buffer_entries = Param.Int(
        "Number of entries in the response buffer."
    )
