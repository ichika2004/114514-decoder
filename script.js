/**
 * RSA x 114514 純數字編碼器 (256-bit 版本)
 */

// 1. 數碼對照表 (0-9)
const HOMO_MAP = [
    "114514", // 0
    "1919",   // 1
    "810",    // 2
    "114",    // 3
    "514",    // 4
    "1919810",    // 5
    "8101919",     // 6
    "5141919",     // 7
    "1145141919",     // 8
    "1145141919810"       // 9
];

/**
 * 將字元轉為純數字：'A' -> 065 -> HOMO_MAP[0]+HOMO_MAP[6]+HOMO_MAP[5]
 */
function encodeToNumbers(code) {
    return code.toString().padStart(3, '0').split('')
        .map(digit => HOMO_MAP[parseInt(digit)]).join('');
}

/**
 * 從數字牆還原：長度優先匹配
 */
function decodeFromNumbers(str) {
    let resultNum = "";
    let tempStr = str;
    while (tempStr.length > 0) {
        let found = false;
        // 由長到短比對，防止 14 與 4 衝突
        for (let i = 0; i < HOMO_BASES_SORTED.length; i++) {
            let item = HOMO_BASES_SORTED[i];
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
        chars.push(String.fromCharCode(parseInt(resultNum.substring(i, i + 3))));
    }
    return chars.join('');
}

// 建立排序後的映射表用於解碼
const HOMO_BASES_SORTED = HOMO_MAP.map((v, i) => ({val: v, index: i}))
    .sort((a, b) => b.val.length - a.val.length);

/**
 * 核心功能
 */
function generateTestKeys() {
    const crypt = new JSEncrypt({ default_key_size: 256 });
    alert("正在生成 256-bit 精簡金鑰...");
    const pub = crypt.getPublicKey();
    const priv = crypt.getPrivateKey();
    
    // 移除 PEM 標籤與換行，使其外觀更精簡
    const shortPub = pub.replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\n|\r/g, "");
    const shortPriv = priv.replace(/-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\n|\r/g, "");

    document.getElementById('encryptKeyInput').value = shortPub;
    if (navigator.clipboard) {
        navigator.clipboard.writeText(shortPriv).then(() => alert("✅ 256-bit 金鑰已複製！"));
    }
}

function doEncrypt() {
    const key = document.getElementById('encryptKeyInput').value;
    const text = document.getElementById('encryptInput').value;
    if (!key || !text) return alert("請輸入公鑰與明文");

    const encryptor = new JSEncrypt();
    encryptor.setPublicKey(formatPEM(key, "PUBLIC"));
    const rsaRes = encryptor.encrypt(text);

    if (!rsaRes) {
        return alert("加密失敗！256-bit 限制約 20 個字元，請嘗試縮短內容。");
    }

    // 轉為純數字密文牆
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
        decryptor.setPrivateKey(formatPEM(key, "PRIVATE"));
        const final = decryptor.decrypt(base64);
        document.getElementById('decryptOutput').innerText = final || "解密失敗：金鑰與密文不匹配";
        localStorage.setItem('rsa_priv_cache', key);
    } catch (e) {
        alert("數字牆解析失敗，請檢查內容完整性。");
    }
}

function formatPEM(raw, type) {
    let c = (raw || "").trim();
    if (c.includes("-----BEGIN")) return c;
    return `-----BEGIN ${type} KEY-----\n${c}\n-----END ${type} KEY-----`;
}

function copyToDecrypt() {
    document.getElementById('decryptInput').value = document.getElementById('encryptOutput').innerText;
}

window.onload = () => {
    document.getElementById('encryptKeyInput').value = localStorage.getItem('rsa_pub_cache') || "";
    document.getElementById('decryptKeyInput').value = localStorage.getItem('rsa_priv_cache') || "";
};