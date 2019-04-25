import sys
import angr
import logging
#logging.getLogger('angr').setLevel('DEBUG')

base_addr = 0x400000
project = angr.Project(sys.argv[1], auto_load_libs=False)

free_map = {}


class FreeHandler(angr.SimProcedure):
    def run(self, ptr):
        caller_address = hex(base_addr + self.state.addr).replace("L","")
        free_ptr = hex(base_addr + self.state.solver.eval(self.state.regs.rdi)).replace("L","")
        print("Free called on: %s" % (free_ptr))
        if not free_ptr in free_map:
            free_map[free_ptr] = caller_address
        else:
            print(
                "Potential Double Free: %s is trying to free %s, which has already been freed by %s"
                % (caller_address, free_ptr, free_map[free_ptr])
            )


def validate_read(state):
    region = hex(state.solver.eval(state.inspect.mem_read_address)).replace("L","")
    length = hex(state.solver.eval(state.inspect.mem_read_length)).replace("L","")
    mem_map = [x for x in range(int(region, 16), int(length, 16))]
    for addr in mem_map:
        if addr in free_map:
            free_call = free_map.get(region)
            print(
                "Potential UAF: %s read from memory freed by %s"
                % (region, free_call)
            )


def validate_write(state):
    region = hex(state.solver.eval(state.inspect.mem_write_address)).replace("L","")
    length = hex(state.solver.eval(state.inspect.mem_write_length)).replace("L","")
    mem_map = [x for x in range(int(region, 16), int(length, 16))]
    for addr in mem_map:
        if addr in free_map:
            free_call = free_map.get(region)
            print(
                "Potential UAF: %s wrote to memory freed by %s"
                % (region, free_call)
            )


project.hook_symbol("free", FreeHandler())

inspector = project.factory.entry_state()
simgr = project.factory.simulation_manager(inspector)

inspector.inspect.b("mem_write", angr.BP_AFTER, action=validate_write)
inspector.inspect.b("mem_read", angr.BP_AFTER, action=validate_read)

simgr.run()
