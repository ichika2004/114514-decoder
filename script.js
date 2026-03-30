/**
 * ---------------------------------------------------------
 * RSA x 114514 惡臭論證器 (Bug-Free 穩定版)
 * 解決 split('+') 導致的解析衝突
 * ---------------------------------------------------------
 */

const HOMO_BASES = [114514, 1919, 810, 514, 114, 51, 4];

// 核心論證演算法
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

function formatPEM(rawKey, type = "PUBLIC") {
    let cleanKey = rawKey.trim();
    if (!cleanKey) return "";
    if (!cleanKey.includes("-----BEGIN")) {
        return `-----BEGIN ${type} KEY-----\n${cleanKey}\n-----END ${type} KEY-----`;
    }
    return cleanKey;
}

// 【加密】
function doEncrypt() {
    const pubKeyRaw = document.getElementById('encryptKeyInput').value;
    const text = document.getElementById('encryptInput').value;
    if (!pubKeyRaw || !text) return alert("請輸入公鑰與明文！");

    const pubKey = formatPEM(pubKeyRaw, "PUBLIC");
    const encryptor = new JSEncrypt();
    encryptor.setPublicKey(pubKey);
    const rsaRes = encryptor.encrypt(text);

    if (!rsaRes) return alert("RSA 加密失敗！");

    // 每個字元包在 [] 裡
    const homoFormula = rsaRes.split('').map(char => {
        return `[${getHomo(char.charCodeAt(0))}]`;
    }).join('+');

    document.getElementById('encryptOutput').innerText = homoFormula;
    localStorage.setItem('rsa_pub_cache', pubKeyRaw);
}

// 【解密】關鍵修復：使用 Regex 匹配 [ ]
function doDecrypt() {
    const privKeyRaw = document.getElementById('decryptKeyInput').value;
    const formula = document.getElementById('decryptInput').value.trim();
    if (!privKeyRaw || !formula) return alert("請輸入私鑰與密文！");

    const privKey = formatPEM(privKeyRaw, "PRIVATE");
    localStorage.setItem('rsa_priv_cache', privKeyRaw);

    try {
        // 使用正則抓取所有 [ ... ] 內容，忽略中間的加號
        const segments = formula.match(/\[(.*?)\]/g);
        if (!segments) throw new Error("找不到有效的算式區段");

        const base64Result = segments.map(seg => {
            // 移除前後的中括號
            const cleanSeg = seg.slice(1, -1);
            // 安全計算
            const val = new Function(`return ${cleanSeg}`)();
            return String.fromCharCode(val);
        }).join('');

        const decryptor = new JSEncrypt();
        decryptor.setPrivateKey(privKey);
        const result = decryptor.decrypt(base64Result);

        if (result) {
            document.getElementById('decryptOutput').innerText = result;
        } else {
            alert("解密失敗：私鑰不正確或密文損壞。");
        }
    } catch (e) {
        console.error("解密錯誤詳情:", e);
        alert("解析失敗：" + e.message);
    }
}

function copyToDecrypt() {
    const result = document.getElementById('encryptOutput').innerText;
    const target = document.getElementById('decryptInput');
    if (result && target && !result.includes("尚未")) {
        target.value = result;
    }
}

function generateTestKeys() {
    const crypt = new JSEncrypt({default_key_size: 1024});
    alert("正在生成金鑰對，請稍候...");
    const pub = crypt.getPublicKey();
    const priv = crypt.getPrivateKey();
    document.getElementById('encryptKeyInput').value = pub;
    if (navigator.clipboard) {
        navigator.clipboard.writeText(priv).then(() => {
            alert("✅ 生成成功！公鑰已填入，私鑰已複製到剪貼簿。");
        });
    }
}

window.onload = function() {
    const pub = localStorage.getItem('rsa_pub_cache');
    const priv = localStorage.getItem('rsa_priv_cache');
    if (pub) document.getElementById('encryptKeyInput').value = pub;
    if (priv) document.getElementById('decryptKeyInput').value = priv;
};