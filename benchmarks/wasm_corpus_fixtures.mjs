/** Five different, project-authored programs with independent JS behavior oracles. */
import assert from "node:assert/strict";

const integers = [-2147483648, -32768, -1, 0, 1, 37, 32767, 2147483647];
const signature = (params, results = ["i32"]) => ({ kind: "func", params, results });
const exported = (name, index, params) => ({ direction: "export", module: null,
  name, kind: "func", index, signature: signature(params), issue: null });
const funcExport = name => ({ name, kind: "function" });

export const fixtures = [
  {
    id: "helper-chain", features: ["multiple functions", "internal helper calls", "i32 overflow"],
    privateNames: ["rg_owned_chain_module", "rg_owned_chain_scale", "rg_owned_chain_scramble",
      "rg_owned_chain_value", "rg_owned_chain_entry"],
    wat: `(module $rg_owned_chain_module
  (func $rg_owned_chain_scale (param $rg_owned_chain_value i32) (result i32)
    local.get $rg_owned_chain_value i32.const 3 i32.mul)
  (func $rg_owned_chain_scramble (param i32) (result i32)
    local.get 0 i32.const 42 i32.xor)
  (func $rg_owned_chain_entry (export "calculate") (param i32) (result i32)
    local.get 0 call $rg_owned_chain_scale call $rg_owned_chain_scramble i32.const 7 i32.add))
`,
    imports: [], exports: [funcExport("calculate")],
    interface: [exported("calculate", 2, ["i32"])],
    visibleOpcodes: ["i32.mul", "i32.xor", "call"],
    execute(instance) {
      const expected = integers.map(value => ((Math.imul(value, 3) ^ 42) + 7) | 0);
      const actual = integers.map(value => instance.exports.calculate(value));
      assert.deepEqual(actual, expected);
      return { numerical_cases: integers.length, trap_cases: 0, host_rejection_cases: 0,
        observations: { inputs: integers, results: actual } };
    },
  },
  {
    id: "import-index", features: ["host function import", "shifted function indices", "host arguments"],
    privateNames: ["rg_owned_import_module", "rg_owned_import_adapter", "rg_owned_import_entry", "rg_owned_import_value"],
    wat: `(module $rg_owned_import_module
  (import "host" "adjust" (func $rg_owned_import_adapter (param i32) (result i32)))
  (func $rg_owned_import_entry (export "run") (param $rg_owned_import_value i32) (result i32)
    local.get $rg_owned_import_value i32.const 2 i32.mul
    call $rg_owned_import_adapter i32.const 7 i32.add))
`,
    imports: [{ module: "host", name: "adjust", kind: "function" }], exports: [funcExport("run")],
    interface: [{ direction: "import", module: "host", name: "adjust", kind: "func", index: 0,
      signature: signature(["i32"]), issue: null }, exported("run", 1, ["i32"])],
    visibleOpcodes: ["i32.mul", "call"],
    imported(context) {
      context.calls = [];
      return { host: { adjust(value) { context.calls.push(value); return (Math.imul(value, 5) + 1) | 0; } } };
    },
    execute(instance, context) {
      const expected = integers.map(value => (Math.imul(Math.imul(value, 2), 5) + 8) | 0);
      const actual = integers.map(value => instance.exports.run(value));
      assert.deepEqual(actual, expected);
      assert.deepEqual(context.calls, integers.map(value => Math.imul(value, 2)));
      return { numerical_cases: integers.length, trap_cases: 0, host_rejection_cases: 0,
        observations: { inputs: integers, results: actual, host_arguments: context.calls } };
    },
  },
  {
    id: "memory-state", features: ["memory and data segment", "mutable global", "stateful stores", "memory growth"],
    privateNames: ["rg_owned_memory_module", "rg_owned_memory_storage", "rg_owned_memory_counter",
      "rg_owned_memory_accumulate", "rg_owned_memory_delta", "rg_owned_memory_next"],
    wat: `(module $rg_owned_memory_module
  (memory $rg_owned_memory_storage (export "memory") 1 2)
  (data (i32.const 0) "\\07\\00\\00\\00")
  (global $rg_owned_memory_counter (mut i32) (i32.const 3))
  (func $rg_owned_memory_accumulate (export "accumulate") (param $rg_owned_memory_delta i32) (result i32)
    (local $rg_owned_memory_next i32)
    global.get $rg_owned_memory_counter local.get $rg_owned_memory_delta i32.add global.set $rg_owned_memory_counter
    i32.const 0 i32.load global.get $rg_owned_memory_counter i32.add local.set $rg_owned_memory_next
    i32.const 0 local.get $rg_owned_memory_next i32.store
    local.get $rg_owned_memory_next))
`,
    imports: [], exports: [{ name: "memory", kind: "memory" }, funcExport("accumulate")],
    interface: [{ direction: "export", module: null, name: "memory", kind: "memory", index: 0,
      signature: { kind: "memory", page_size: "65536", address_type: "i32", minimum: "1", maximum: "2", shared: false },
      issue: null }, exported("accumulate", 0, ["i32"])],
    visibleOpcodes: ["i32.load", "i32.store", "global.set"],
    execute(instance) {
      const inputs = [-4, 0, 1, 7, 2147483647, -2147483648];
      let counter = 3, cell = 7;
      const results = [], expected = [], cells = [];
      assert.equal(new DataView(instance.exports.memory.buffer).getInt32(0, true), cell);
      for (const value of inputs) {
        counter = (counter + value) | 0;
        cell = (cell + counter) | 0;
        expected.push(cell);
        results.push(instance.exports.accumulate(value));
        cells.push(new DataView(instance.exports.memory.buffer).getInt32(0, true));
      }
      assert.deepEqual(results, expected);
      assert.deepEqual(cells, expected);
      const oldPages = instance.exports.memory.grow(1);
      assert.equal(oldPages, 1);
      assert.equal(instance.exports.memory.buffer.byteLength, 2 * 65536);
      assert.equal(new DataView(instance.exports.memory.buffer).getInt32(0, true), cell);
      assert.throws(() => instance.exports.memory.grow(1), RangeError);
      return { numerical_cases: inputs.length, trap_cases: 0, host_rejection_cases: 1,
        observations: { inputs, results, memory_cells: cells, old_pages: oldPages, grown_pages: 2 } };
    },
  },
  {
    id: "table-dispatch", features: ["function table", "element segment", "indirect call", "table mutation and traps"],
    privateNames: ["rg_owned_table_module", "rg_owned_table_plus", "rg_owned_table_scale", "rg_owned_table_dispatch",
      "rg_owned_table_selector", "rg_owned_table_value"],
    wat: `(module $rg_owned_table_module
  (type $operation (func (param i32) (result i32)))
  (func $rg_owned_table_plus (type $operation) (param i32) (result i32) local.get 0 i32.const 7 i32.add)
  (func $rg_owned_table_scale (type $operation) (param i32) (result i32) local.get 0 i32.const 3 i32.mul)
  (table (export "table") 2 2 funcref)
  (elem (i32.const 0) $rg_owned_table_plus $rg_owned_table_scale)
  (func $rg_owned_table_dispatch (export "dispatch")
    (param $rg_owned_table_selector i32) (param $rg_owned_table_value i32) (result i32)
    local.get $rg_owned_table_value local.get $rg_owned_table_selector call_indirect (type $operation)))
`,
    imports: [], exports: [{ name: "table", kind: "table" }, funcExport("dispatch")],
    interface: [{ direction: "export", module: null, name: "table", kind: "table", index: 0,
      signature: { kind: "table", element: "funcref", address_type: "i32", minimum: "2", maximum: "2", shared: false },
      issue: null }, exported("dispatch", 2, ["i32", "i32"])],
    visibleOpcodes: ["call_indirect", "i32.mul", "i32.add"],
    execute(instance) {
      const values = [-2147483648, -1, 0, 1, 2147483647], observations = [];
      for (const selector of [0, 1]) {
        const results = values.map(value => instance.exports.dispatch(selector, value));
        const expected = values.map(value => selector === 0 ? (value + 7) | 0 : Math.imul(value, 3));
        assert.deepEqual(results, expected);
        observations.push({ selector, values, results });
      }
      for (const selector of [2, -1]) assert.throws(() => instance.exports.dispatch(selector, 5), WebAssembly.RuntimeError);
      instance.exports.table.set(0, instance.exports.table.get(1));
      assert.equal(instance.exports.dispatch(0, 17), 51);
      return { numerical_cases: values.length * 2 + 1, trap_cases: 2, host_rejection_cases: 0,
        observations: { calls: observations, mutated_table_result: 51 } };
    },
  },
  {
    id: "bounded-loop", features: ["conditional returns", "loop and branches", "local state", "input limits"],
    privateNames: ["rg_owned_loop_module", "rg_owned_loop_sum", "rg_owned_loop_limit", "rg_owned_loop_index", "rg_owned_loop_total"],
    wat: `(module $rg_owned_loop_module
  (func $rg_owned_loop_sum (export "sum") (param $rg_owned_loop_limit i32) (result i32)
    (local $rg_owned_loop_index i32) (local $rg_owned_loop_total i32)
    local.get $rg_owned_loop_limit i32.const 0 i32.lt_s if i32.const -1 return end
    local.get $rg_owned_loop_limit i32.const 1000 i32.gt_s if i32.const -2 return end
    block $done
      loop $again
        local.get $rg_owned_loop_index local.get $rg_owned_loop_limit i32.ge_u br_if $done
        local.get $rg_owned_loop_index i32.const 1 i32.add local.set $rg_owned_loop_index
        local.get $rg_owned_loop_total local.get $rg_owned_loop_index i32.add local.set $rg_owned_loop_total
        br $again
      end
    end
    local.get $rg_owned_loop_total))
`,
    imports: [], exports: [funcExport("sum")], interface: [exported("sum", 0, ["i32"])],
    visibleOpcodes: ["loop", "br_if", "i32.ge_u", "return"],
    execute(instance) {
      const inputs = [-2147483648, -1, 0, 1, 2, 3, 31, 1000, 1001, 2147483647];
      const expected = inputs.map(value => value < 0 ? -1 : value > 1000 ? -2 : value * (value + 1) / 2);
      const results = inputs.map(value => instance.exports.sum(value));
      assert.deepEqual(results, expected);
      return { numerical_cases: inputs.length, trap_cases: 0, host_rejection_cases: 0, observations: { inputs, results } };
    },
  },
];

export const linkerFixture = {
  id: "relocatable-linker-leak", privateNames: ["rg_owned_link_internal"],
  wat: `(module $rg_owned_link_module
  (func $rg_owned_link_internal (param i32) (result i32) local.get 0 i32.const 7 i32.mul)
  (func (export "quote") (param i32) (result i32) local.get 0 call $rg_owned_link_internal i32.const 3 i32.add))
`,
  imports: [], exports: [funcExport("quote")], interface: [exported("quote", 1, ["i32"])],
  visibleOpcodes: ["call", "i32.mul", "i32.add"],
  execute(instance) {
    const expected = integers.map(value => (Math.imul(value, 7) + 3) | 0);
    const results = integers.map(value => instance.exports.quote(value));
    assert.deepEqual(results, expected);
    return { numerical_cases: integers.length, trap_cases: 0, host_rejection_cases: 0, observations: { inputs: integers, results } };
  },
};
