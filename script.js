/**
 * RSA x 114514 純數字論證器
 * 特色：使用 0 作為分隔號，保留完整 PEM 前後綴
 */

const HOMO_MAP = [
    "114514",         // 0
    "1919",           // 1
    "81",             // 2 
    "114",            // 3
    "514",            // 4
    "191981",         // 5 
    "811919",         // 6 
    "5141919",        // 7
    "1145141919",     // 8
    "114514191981"    // 9 (原本 1145141919810)
];

const SEPARATOR = "0";

/**
 * 編碼邏輯
 */
function encodeToNumbers(code) {
    return code.toString().padStart(3, '0').split('')
        .map(digit => HOMO_MAP[parseInt(digit)])
        .join(SEPARATOR);
}

/**
 * 解碼邏輯 (精確切割 0)
 */
function decodeFromNumbers(str) {
    const parts = str.split(SEPARATOR);
    let resultNum = "";
    parts.forEach(part => {
        const index = HOMO_MAP.indexOf(part);
        if (index !== -1) resultNum += index.toString();
    });
    let chars = [];
    for (let i = 0; i < resultNum.length; i += 3) {
        let code = resultNum.substring(i, i + 3);
        if (code.length === 3) chars.push(String.fromCharCode(parseInt(code)));
    }
    return chars.join('');
}

/**
 *  生成 256-bit 金鑰 (完整 PEM 格式)
 */
function generateTestKeys() {
    const crypt = new JSEncrypt({ default_key_size: 256 });
    alert("正在生成標準 256-bit PEM 金鑰...");
    
    const pub = crypt.getPublicKey();   // 帶有 -----BEGIN PUBLIC KEY-----
    const priv = crypt.getPrivateKey(); // 帶有 -----BEGIN PRIVATE KEY-----
    
    document.getElementById('encryptKeyInput').value = pub;
    document.getElementById('decryptKeyInput').value = priv;

    localStorage.setItem('rsa_pub_cache', pub);
    localStorage.setItem('rsa_priv_cache', priv);
    
    if (navigator.clipboard) {
        navigator.clipboard.writeText(priv).then(() => alert("金鑰已同步填入，私鑰已複製！"));
    }
}

function doEncrypt() {
    const key = document.getElementById('encryptKeyInput').value;
    const text = document.getElementById('encryptInput').value;
    if (!key || !text) return alert("請輸入公鑰與明文");

    const encryptor = new JSEncrypt();
    encryptor.setPublicKey(key);
    const rsaRes = encryptor.encrypt(text);

    if (!rsaRes) return alert("加密失敗！256-bit 空間有限，請縮短文字。");

    // 用 0 串接所有數碼
    const result = rsaRes.split('').map(c => encodeToNumbers(c.charCodeAt(0))).join(SEPARATOR);
    document.getElementById('encryptOutput').innerText = result;
    localStorage.setItem('rsa_pub_cache', key);
}

function doDecrypt() {
    const key = document.getElementById('decryptKeyInput').value;
    const formula = document.getElementById('decryptInput').value.trim();
    if (!key || !formula) return alert("請輸入私鑰與密文");

    try {
        const base64 = decodeFromNumbers(formula);
        const decryptor = new JSEncrypt();
        decryptor.setPrivateKey(key);
        const final = decryptor.decrypt(base64);
        
        document.getElementById('decryptOutput').innerText = final || "解密失敗：金鑰不匹配";
        localStorage.setItem('rsa_priv_cache', key);
    } catch (e) {
        alert("數字牆解析失敗。");
    }
}

function copyToDecrypt() {
    document.getElementById('decryptInput').value = document.getElementById('encryptOutput').innerText;
}

window.onload = () => {
    const savedPub = localStorage.getItem('rsa_pub_cache');
    const savedPriv = localStorage.getItem('rsa_priv_cache');
    if (savedPub) document.getElementById('encryptKeyInput').value = savedPub;
    if (savedPriv) document.getElementById('decryptKeyInput').value = savedPriv;
};