import sys
import angr

project = angr.Project(sys.argv[1], auto_load_libs=False)

free_map = {}


class FreeHandler(angr.SimProcedure):
    def run(self):
        caller_address = self.state.addr
        free_ptr = self.state.regs.rdi
        print("Free called on: %s" % (free_ptr))
        free_map[free_ptr] = caller_address


def validate_read(state):
    region = state.inspect.mem_read_address
    if region in free_map:
        free_call = free_map.get(region)
        print("%s read from memory freed by %s" % (region, free_call))


def validate_write(state):
    region = state.inspect.mem_write_address
    if region in free_map:
        free_call = free_map.get(region)
        print("%s wrote to memory freed by %s" % (region, free_call))


project.hook_symbol("free", FreeHandler())

simgr = project.factory.simulation_manager()
inspector = project.factory.entry_state()

inspector.inspect.b("mem_write", when=angr.BP_AFTER, action=validate_write)
inspector.inspect.b("mem_read", when=angr.BP_AFTER, action=validate_read)

simgr.run()
