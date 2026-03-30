/**
 * 核心惡臭論證演算法
 * 參考 https://lab.magiconch.com/homo/
 */
const HOMO_BASES = [114514, 1919, 810, 114, 514, 191, 81, 14, 5, 4, 1];

function getHomo(n) {
    if (n === 0) return "(114514-114514)";
    if (n < 0) return `-( ${getHomo(Math.abs(n))} )`;

    // 為了確保 1919 和 810 出現，我們對較小的 ASCII 碼進行「補數論證」
    // 邏輯：n = (1919 + 810) - (1919 + 810 - n)
    if (n < 810) {
        const offset = 1919 + 810;
        return `(${offset}-(${simpleHomo(offset - n)}))`;
    }
    return simpleHomo(n);
}

// 基礎遞迴拆解
function simpleHomo(n) {
    if (HOMO_BASES.includes(n)) return n.toString();
    if (n === 1) return "1";

    for (let b of HOMO_BASES) {
        if (n >= b && b > 1) {
            let q = Math.floor(n / b);
            let r = n % b;
            let qStr = (q === 1) ? "" : `*(${simpleHomo(q)})`;
            let res = `${b}${qStr}`;
            if (r > 0) res += `+(${simpleHomo(r)})`;
            return res;
        }
    }
    return new Array(n).fill("1").join("+");
}

function formatPEM(raw, type) {
    let c = (raw || "").trim();
    return c.includes("-----BEGIN") ? c : `-----BEGIN ${type} KEY-----\n${c}\n-----END ${type} KEY-----`;
}

// 【加密】
function doEncrypt() {
    const key = document.getElementById('encryptKeyInput').value;
    const text = document.getElementById('encryptInput').value;
    if (!key || !text) return alert("請填寫公鑰與明文");

    const encryptor = new JSEncrypt();
    encryptor.setPublicKey(formatPEM(key, "PUBLIC"));
    const rsa = encryptor.encrypt(text);
    if (!rsa) return alert("加密失敗，請檢查金鑰");

    // 轉化為 1145141919810 算式牆
    const result = rsa.split('').map(c => `[${getHomo(c.charCodeAt(0))}]`).join('');
    document.getElementById('encryptOutput').innerText = result;
    localStorage.setItem('rsa_pub', key);
}

// 【解密】
function doDecrypt() {
    const key = document.getElementById('decryptKeyInput').value;
    const formula = document.getElementById('decryptInput').value.trim();
    if (!key || !formula) return alert("請填寫私鑰與算式");

    try {
        const segments = formula.match(/\[(.*?)\]/g);
        if (!segments) throw new Error("無效的算式格式");

        const base64 = segments.map(seg => {
            const clean = seg.slice(1, -1);
            return String.fromCharCode(new Function(`return ${clean}`)());
        }).join('');

        const decryptor = new JSEncrypt();
        decryptor.setPrivateKey(formatPEM(key, "PRIVATE"));
        const final = decryptor.decrypt(base64);
        
        if (final) {
            document.getElementById('decryptOutput').innerText = final;
        } else {
            alert("解密失敗：私鑰不匹配");
        }
    } catch (e) {
        alert("解析失敗：" + e.message);
    }
}

function generateTestKeys() {
    const crypt = new JSEncrypt({default_key_size: 1024});
    alert("正在生成金鑰，這可能需要幾秒鐘...");
    const pub = crypt.getPublicKey();
    const priv = crypt.getPrivateKey();
    document.getElementById('encryptKeyInput').value = pub;
    if (navigator.clipboard) {
        navigator.clipboard.writeText(priv).then(() => alert("✅ 公鑰已填入，私鑰已自動複製！"));
    }
}

function copyToDecrypt() {
    const res = document.getElementById('encryptOutput').innerText;
    if (res.length > 20) document.getElementById('decryptInput').value = res;
}

window.onload = () => {
    document.getElementById('encryptKeyInput').value = localStorage.getItem('rsa_pub') || "";
    document.getElementById('decryptKeyInput').value = localStorage.getItem('rsa_priv') || "";
};