/**
 * RSA x 114514 純數字編碼器 (256-bit 穩定版)
 * 修復：金鑰自動填入、快取一致性、長度優先匹配
 */

const HOMO_MAP = [
    "114514", "1919", "810", "114", "514", 
    "1919810", "8101919", "5141919", "1145141919", "1145141919810"
];

const LOOKUP = HOMO_MAP.map((val, index) => ({ val, index }))
    .sort((a, b) => b.val.length - a.val.length);

/**
 * 數碼編解碼
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
 * 🚀 修復後的金鑰生成 (同時填入兩個欄位)
 */
function generateTestKeys() {
    const crypt = new JSEncrypt({ default_key_size: 256 });
    alert("正在生成 256-bit 金鑰對並同步填入...");
    
    const pub = crypt.getPublicKey();
    const priv = crypt.getPrivateKey();
    
    // 移除 PEM 標籤使介面精簡
    const shortPub = pub.replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\n|\r/g, "");
    const shortPriv = priv.replace(/-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\n|\r/g, "");

    // 【核心修復】同時填入兩個欄位
    document.getElementById('encryptKeyInput').value = shortPub;
    document.getElementById('decryptKeyInput').value = shortPriv;

    // 同步更新 LocalStorage
    localStorage.setItem('rsa_pub_cache', shortPub);
    localStorage.setItem('rsa_priv_cache', shortPriv);
    
    if (navigator.clipboard) {
        navigator.clipboard.writeText(shortPriv).then(() => {
            alert("金鑰生成成功！\n1. 公鑰已填入加密區。\n2. 私鑰已填入解密區並複製到剪貼簿。");
        });
    }
}

/**
 * 加密與解密邏輯
 */
function doEncrypt() {
    const key = document.getElementById('encryptKeyInput').value;
    const text = document.getElementById('encryptInput').value;
    if (!key || !text) return alert("請輸入公鑰與明文");

    const encryptor = new JSEncrypt();
    encryptor.setPublicKey(formatPEM(key, "PUBLIC"));
    const rsaRes = encryptor.encrypt(text);

    if (!rsaRes) return alert("加密失敗！內容過長，請縮短文字。");

    const result = rsaRes.split('').map(c => encodeToNumbers(c.charCodeAt(0))).join('');
    document.getElementById('encryptOutput').innerText = result;
    
    // 儲存當前使用的公鑰
    localStorage.setItem('rsa_pub_cache', key);
}

function doDecrypt() {
    const key = document.getElementById('decryptKeyInput').value;
    const formula = document.getElementById('decryptInput').value.trim();
    if (!key || !formula) return alert("請輸入私鑰與密文");

    try {
        const base64 = decodeFromNumbers(formula);
        const decryptor = new JSEncrypt();
        decryptor.setPrivateKey(formatPEM(key, "PRIVATE"));
        const final = decryptor.decrypt(base64);
        
        document.getElementById('decryptOutput').innerText = final || "解密失敗：金鑰與密文不匹配";
        
        // 儲存當前使用的私鑰
        localStorage.setItem('rsa_priv_cache', key);
    } catch (e) {
        alert("數字牆解析失敗。");
    }
}

function formatPEM(raw, type) {
    let c = (raw || "").trim();
    if (c.includes("-----BEGIN")) return c;
    return `-----BEGIN ${type} KEY-----\n${c}\n-----END ${type} KEY-----`;
}

function copyToDecrypt() {
    const content = document.getElementById('encryptOutput').innerText;
    if (content.length > 5) {
        document.getElementById('decryptInput').value = content;
    }
}

/**
 * 頁面載入時正確恢復兩個金鑰
 */
window.onload = () => {
    const savedPub = localStorage.getItem('rsa_pub_cache');
    const savedPriv = localStorage.getItem('rsa_priv_cache');
    
    if (savedPub) document.getElementById('encryptKeyInput').value = savedPub;
    if (savedPriv) document.getElementById('decryptKeyInput').value = savedPriv;
};