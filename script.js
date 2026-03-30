/**
 * ---------------------------------------------------------
 * RSA x 114514 惡臭論證加密器 (v7.0 MagicConch Style)
 * ---------------------------------------------------------
 */

const HOMO_BASES = [114514, 1919, 810, 514, 114, 51, 4];

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

function doEncrypt() {
    const pubKeyEl = document.getElementById('encryptKeyInput');
    const textEl = document.getElementById('encryptInput');
    
    if (!pubKeyEl || !textEl) return console.error("找不到加密輸入欄位！");

    const pubKeyRaw = pubKeyEl.value;
    const text = textEl.value;
    
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

function doDecrypt() {
    const privKeyEl = document.getElementById('decryptKeyInput');
    const formulaEl = document.getElementById('decryptInput');

    if (!privKeyEl || !formulaEl) return console.error("找不到解密輸入欄位！");

    const privKeyRaw = privKeyEl.value;
    const formula = formulaEl.value.trim();

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

function copyToDecrypt() {
    const result = document.getElementById('encryptOutput').innerText;
    const decryptTarget = document.getElementById('decryptInput');
    if (result.includes("尚未") || !decryptTarget) return;
    decryptTarget.value = result;
}

function generateTestKeys() {
    const crypt = new JSEncrypt({default_key_size: 1024});
    alert("正在生成金鑰對...");
    const pub = crypt.getPublicKey();
    const priv = crypt.getPrivateKey();
    
    const encryptKeyInput = document.getElementById('encryptKeyInput');
    if (encryptKeyInput) encryptKeyInput.value = pub;
    
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(priv).then(() => {
            alert("✅ 生成成功！公鑰已填入，私鑰已複製。");
        });
    }
}

window.onload = function() {
    const savedPub = localStorage.getItem('rsa_pub_cache');
    const savedPriv = localStorage.getItem('rsa_priv_cache');
    
    const pubInput = document.getElementById('encryptKeyInput');
    const privInput = document.getElementById('decryptKeyInput');
    
    if (pubInput && savedPub) pubInput.value = savedPub;
    if (privInput && savedPriv) privInput.value = savedPriv;
};