/**
 * ---------------------------------------------------------
 * RSA x 114514 惡臭論證加密器 (v7.0 MagicConch Style)
 * ---------------------------------------------------------
 */

// 核心惡臭基數 (排除 1 以防止遞迴死循環)
const HOMO_BASES = [114514, 1919, 810, 514, 114, 51, 4];

/**
 * 惡臭論證演算法 (修正版：防止堆疊溢位)
 */
function getHomo(n) {
    if (n === 0) return "0";
    if (n < 0) return `-( ${getHomo(Math.abs(n))} )`;
    if (HOMO_BASES.includes(n)) return n.toString();
    if (n === 1) return "1";

    for (let b of HOMO_BASES) {
        if (n >= b) {
            let q = Math.floor(n / b);
            let r = n % b;
            let qStr = (q === 1) ? "" : `*(${getHomo(q)})`;
            let res = `${b}${qStr}`;
            if (r > 0) res += `+(${getHomo(r)})`;
            return res;
        }
    }
    return new Array(n).fill("1").join("+");
}

/**
 * 自動修補 PEM 標籤
 */
function formatPEM(rawKey, type = "PUBLIC") {
    let cleanKey = rawKey.trim();
    if (!cleanKey) return "";
    if (!cleanKey.includes("-----BEGIN")) {
        return `-----BEGIN ${type} KEY-----\n${cleanKey}\n-----END ${type} KEY-----`;
    }
    return cleanKey;
}

/**
 * 加密：從加密專區讀取
 */
function doEncrypt() {
    const pubKeyRaw = document.getElementById('encryptKeyInput').value;
    const text = document.getElementById('encryptInput').value;
    
    if (!pubKeyRaw || !text) return alert("請輸入公鑰與明文！");

    const pubKey = formatPEM(pubKeyRaw, "PUBLIC");
    localStorage.setItem('rsa_pub_cache', pubKeyRaw);

    const encryptor = new JSEncrypt();
    encryptor.setPublicKey(pubKey);
    const rsaRes = encryptor.encrypt(text);

    if (!rsaRes) return alert("RSA 加密失敗！");

    const homoFormula = rsaRes.split('').map(char => {
        return `[${getHomo(char.charCodeAt(0))}]`;
    }).join('+');

    document.getElementById('encryptOutput').innerText = homoFormula;
}

/**
 * 解密：從解密專區讀取
 */
function doDecrypt() {
    const privKeyRaw = document.getElementById('decryptKeyInput').value;
    const formula = document.getElementById('decryptInput').value.trim();

    if (!privKeyRaw || !formula) return alert("請輸入私鑰與密文！");

    const privKey = formatPEM(privKeyRaw, "PRIVATE");
    localStorage.setItem('rsa_priv_cache', privKeyRaw);

    try {
        const base64Result = formula.split('+')
            .map(s => s.trim())
            .filter(s => s.length > 0)
            .map(seg => {
                const cleanSeg = seg.replace(/[\[\]]/g, '').trim();
                const val = new Function(`return ${cleanSeg}`)();
                return String.fromCharCode(val);
            }).join('');

        const decryptor = new JSEncrypt();
        decryptor.setPrivateKey(privKey);
        const result = decryptor.decrypt(base64Result);

        if (result) {
            document.getElementById('decryptOutput').innerText = result;
        } else {
            alert("解密失敗！私鑰可能不正確。");
        }
    } catch (e) {
        alert("算式解析失敗。");
    }
}

/**
 * 一鍵複製加密結果到解密框
 */
function copyToDecrypt() {
    const result = document.getElementById('encryptOutput').innerText;
    if (result.includes("尚未")) return;
    document.getElementById('decryptInput').value = result;
}

/**
 * 生成金鑰並自動複製私鑰
 */
function generateTestKeys() {
    const crypt = new JSEncrypt({default_key_size: 1024});
    alert("正在生成金鑰對...");
    
    const pub = crypt.getPublicKey();
    const priv = crypt.getPrivateKey();
    
    document.getElementById('encryptKeyInput').value = pub;
    
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(priv).then(() => {
            alert("✅ 生成成功！\n1. 公鑰已填入。\n2. 私鑰已自動複製到剪貼簿。");
        });
    }
}

// 載入緩存
window.onload = function() {
    const savedPub = localStorage.getItem('rsa_pub_cache');
    const savedPriv = localStorage.getItem('rsa_priv_cache');
    if (savedPub) document.getElementById('encryptKeyInput').value = savedPub;
    if (savedPriv) document.getElementById('decryptKeyInput').value = savedPriv;
};