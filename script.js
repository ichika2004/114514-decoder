/**
 * RSA x 114514 純數字論證器 (NSYSU IM 穩定版)
 * 定製：256-bit 分段加密 + 0 位隔離編碼
 */

// 映射表：移除結尾的 0，因為 SEP = "0"，拼接後視覺效果依然是 810
const HOMO_MAP = [
    "114514",       // 0
    "1919",         // 1
    "81",           // 2 (與 SEP 拼接後視覺為 810)
    "114",          // 3
    "514",          // 4
    "889464",       // 5 
    "364",          // 6 
    "931",          // 7
    "893",          // 8
    "1145141919"    // 9 
];

const SEP = "0";     // 數碼分隔符
const B_SEP = "00";  // RSA 區塊分隔符

/**
 * 編碼：將 ASCII 碼轉為純數字序列
 */
function encodeToNumbers(code) {
    return code.toString().padStart(3, '0').split('')
        .map(digit => HOMO_MAP[parseInt(digit)])
        .join(SEP);
}

/**
 * 解碼：精確切割分隔符並還原
 */
function decodeFromNumbers(str) {
    if (!str) return "";
    // split(SEP) 會把 0 濾掉，留下原始數碼
    const parts = str.split(SEP).filter(p => p.length > 0);
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
    alert("正在生成 256-bit 標準 PEM 金鑰...");
    
    const pub = crypt.getPublicKey();
    const priv = crypt.getPrivateKey();
    
    document.getElementById('encryptKeyInput').value = pub;
    document.getElementById('decryptKeyInput').value = priv;

    localStorage.setItem('rsa_pub_cache', pub);
    localStorage.setItem('rsa_priv_cache', priv);
    
    if (navigator.clipboard) {
        navigator.clipboard.writeText(priv).then(() => {
            alert("金鑰生成成功！\n1. 公私鑰已完整填入。\n2. 私鑰已同步複製。");
        });
    }
}

/**
 * 加密功能 (支援長文本分段)
 */
function doEncrypt() {
    const key = document.getElementById('encryptKeyInput').value.trim();
    const text = document.getElementById('encryptInput').value;
    if (!key || !text) return alert("請輸入公鑰與明文");

    const encryptor = new JSEncrypt();
    encryptor.setPublicKey(key);

    // 256-bit 安全分段長度
    const CHUNK_SIZE = 5;
    let blocks = [];

    for (let i = 0; i < text.length; i += CHUNK_SIZE) {
        const chunk = text.substring(i, i + CHUNK_SIZE);
        const rsaRes = encryptor.encrypt(chunk);
        if (!rsaRes) continue;
        
        const homoBlock = rsaRes.split('').map(c => encodeToNumbers(c.charCodeAt(0))).join(SEP);
        blocks.push(homoBlock);
    }

    document.getElementById('encryptOutput').innerText = blocks.join(B_SEP);
    localStorage.setItem('rsa_pub_cache', key);
}

/**
 * 解密功能 (分段還原)
 */
function doDecrypt() {
    const key = document.getElementById('decryptKeyInput').value.trim();
    const formula = document.getElementById('decryptInput').value.trim();
    if (!key || !formula) return alert("請輸入私鑰與密文");

    const decryptor = new JSEncrypt();
    decryptor.setPrivateKey(key);

    try {
        // 先按區塊分隔符 (00) 切開
        const blocks = formula.split(B_SEP).filter(b => b.length > 5);
        let finalResult = "";

        blocks.forEach((block) => {
            const base64 = decodeFromNumbers(block);
            const decrypted = decryptor.decrypt(base64);
            if (decrypted) finalResult += decrypted;
        });

        document.getElementById('decryptOutput').innerText = finalResult || "解密失敗：金鑰不匹配";
        localStorage.setItem('rsa_priv_cache', key);
    } catch (e) {
        alert("數字牆格式損壞。");
    }
}

/**
 * 輔助功能
 */
function copyToDecrypt() {
    const res = document.getElementById('encryptOutput').innerText;
    if (res.length > 5) document.getElementById('decryptInput').value = res;
}

window.onload = () => {
    const savedPub = localStorage.getItem('rsa_pub_cache');
    const savedPriv = localStorage.getItem('rsa_priv_cache');
    if (savedPub) document.getElementById('encryptKeyInput').value = savedPub;
    if (savedPriv) document.getElementById('decryptKeyInput').value = savedPriv;
};