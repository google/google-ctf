# Copyright 2019 Google LLC

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     https://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import blif
import arch

p = blif.get_parser()
parsed = p.parse(open("/tmp/synth.blif").read())
transformed = blif.BlifTransformer().transform(parsed)
conf = arch.Configuration.from_model(transformed)

print(conf)

with open("/tmp/synth.bin", "wb") as fb:
    fb.write(conf.as_bin())

with open("/tmp/synth.portmap", "w") as fpm:
    fpm.writelines(
        "in {} at {:#x}\n".format(name, loc.loci) for name, loc in conf.inputs.items()
    )
    fpm.write("\n")
    fpm.writelines(
        "out {} at {:#x} ({:#x})\n".format(name, loc.loci, loc.loci - conf.port_bits)
        for name, loc in conf.outputs.items()
    )
    fpm.write("\n")
    fpm.writelines(
        "internal {} at {:#x} ({:#x})\n".format(
            name, loc.loci, loc.loci - conf.port_bits
        )
        for name, loc in conf.inner_vars.items()
    )
