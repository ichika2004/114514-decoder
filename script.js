/**
 * RSA x 114514 純數字論證編碼器
 * 修復：保留完整 PEM 前後綴、優化自動填入邏輯
 */

const HOMO_MAP = [
    "114514", "1919", "810", "114", "514", 
    "1919810", "8101919", "5141919", "1145141919", "1145141919810"
];

// 建立解碼查找表
const LOOKUP = HOMO_MAP.map((val, index) => ({ val, index }))
    .sort((a, b) => b.val.length - a.val.length);

/**
 * 數碼編解碼演算法
 */
function encodeToNumbers(code) {
    return code.toString().padStart(3, '0').split('')
        .map(digit => HOMO_MAP[parseInt(digit)]).join('');
}

function decodeFromNumbers(str) {
    let resultNum = "";
    let tempStr = str;
    while (tempStr.length > 0) {
        let found = false;
        for (let item of LOOKUP) {
            if (tempStr.startsWith(item.val)) {
                resultNum += item.index;
                tempStr = tempStr.substring(item.val.length);
                found = true;
                break;
            }
        }
        if (!found) break;
    }
    let chars = [];
    for (let i = 0; i < resultNum.length; i += 3) {
        let code = resultNum.substring(i, i + 3);
        if (code.length === 3) chars.push(String.fromCharCode(parseInt(code)));
    }
    return chars.join('');
}

/**
 * 🚀 修復後的金鑰生成：保留完整前後綴
 */
function generateTestKeys() {
    const crypt = new JSEncrypt({ default_key_size: 256 });
    alert("正在生成 256-bit 標準 PEM 金鑰...");
    
    const pub = crypt.getPublicKey();   // 這裡原本就帶有前後綴
    const priv = crypt.getPrivateKey(); // 這裡原本就帶有前後綴
    
    // 【修正】直接填入完整金鑰，不再進行 replace 濾除
    document.getElementById('encryptKeyInput').value = pub;
    document.getElementById('decryptKeyInput').value = priv;

    // 更新快取
    localStorage.setItem('rsa_pub_cache', pub);
    localStorage.setItem('rsa_priv_cache', priv);
    
    if (navigator.clipboard) {
        navigator.clipboard.writeText(priv).then(() => {
            alert(" 金鑰生成成功！\n1. 公鑰與私鑰已完整填入。\n2. 私鑰已同步複製到剪貼簿。");
        });
    }
}

/**
 * 加密與解密功能
 */
function doEncrypt() {
    const key = document.getElementById('encryptKeyInput').value;
    const text = document.getElementById('encryptInput').value;
    if (!key || !text) return alert("請輸入公鑰與明文");

    const encryptor = new JSEncrypt();
    // 這裡 setPublicKey 可以處理帶有或不帶有標籤的金鑰
    encryptor.setPublicKey(key); 
    const rsaRes = encryptor.encrypt(text);

    if (!rsaRes) return alert("加密失敗！內容可能過長。");

    const result = rsaRes.split('').map(c => encodeToNumbers(c.charCodeAt(0))).join('');
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
    const content = document.getElementById('encryptOutput').innerText;
    if (content.length > 5) {
        document.getElementById('decryptInput').value = content;
    }
}

window.onload = () => {
    const savedPub = localStorage.getItem('rsa_pub_cache');
    const savedPriv = localStorage.getItem('rsa_priv_cache');
    
    if (savedPub) document.getElementById('encryptKeyInput').value = savedPub;
    if (savedPriv) document.getElementById('decryptKeyInput').value = savedPriv;
};