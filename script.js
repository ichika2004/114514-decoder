/**
 * 114514 核心論證演算法 (純淨數碼版)
 */
const HOMO_BASES = [114514, 1919, 810, 114, 514, 191, 81, 14, 51, 4, 1];

function getHomo(n) {
    if (n === 0) return "(114-114)";
    if (n < 0) return `-( ${getHomo(Math.abs(n))} )`;

    // 為了讓大數字 114514, 1919, 810 必定出現
    // 我們使用「強制展開法」：n = 114514 + 1919 + 810 - (114514 + 1919 + 810 - n)
    // 這樣字串裡就只會出現這些數碼，而不會出現它們相加後的結果
    const target = 114514 + 1919 + 810;
    const diff = target - n;

    // 這裡我們直接寫死字串，確保 2729 不會出現
    return `(114514+1919+810-(${simpleDecompose(diff)}))`;
}

// 基礎遞迴拆解：只使用 HOMO_BASES 中的數字
function simpleDecompose(n) {
    if (n === 0) return "0";
    for (let b of HOMO_BASES) {
        if (n >= b) {
            if (n === b) return b.toString();
            // 這裡必須使用基數 b，剩下的繼續遞迴
            return `${b}+(${simpleDecompose(n - b)})`;
        }
    }
}

/**
 * 加密與解密邏輯
 */
function doEncrypt() {
    const key = document.getElementById('encryptKeyInput').value;
    const text = document.getElementById('encryptInput').value;
    if (!key || !text) return alert("請填寫公鑰與明文");

    const encryptor = new JSEncrypt();
    encryptor.setPublicKey(formatPEM(key, "PUBLIC"));
    const rsa = encryptor.encrypt(text);
    if (!rsa) return alert("RSA 加密失敗");

    // 轉化為純淨惡臭算式牆
    const result = rsa.split('').map(c => `[${getHomo(c.charCodeAt(0))}]`).join('');
    document.getElementById('encryptOutput').innerText = result;
    localStorage.setItem('rsa_pub', key);
}

function doDecrypt() {
    const key = document.getElementById('decryptKeyInput').value;
    const formula = document.getElementById('decryptInput').value.trim();
    if (!key || !formula) return alert("請填寫私鑰與算式");

    try {
        const segments = formula.match(/\[(.*?)\]/g);
        const base64 = segments.map(seg => {
            const clean = seg.slice(1, -1);
            // new Function 會幫我們計算 (114514+1919+810-...) 的值
            return String.fromCharCode(new Function(`return ${clean}`)());
        }).join('');

        const decryptor = new JSEncrypt();
        decryptor.setPrivateKey(formatPEM(key, "PRIVATE"));
        const final = decryptor.decrypt(base64);
        document.getElementById('decryptOutput').innerText = final || "解密失敗：金鑰不匹配";
    } catch (e) {
        alert("解析失敗：" + e.message);
    }
}

// 其餘輔助函式
function formatPEM(raw, type) {
    let c = (raw || "").trim();
    return c.includes("-----BEGIN") ? c : `-----BEGIN ${type} KEY-----\n${c}\n-----END ${type} KEY-----`;
}

function generateTestKeys() {
    const crypt = new JSEncrypt({default_key_size: 1024});
    alert("正在生成金鑰...");
    const pub = crypt.getPublicKey();
    const priv = crypt.getPrivateKey();
    document.getElementById('encryptKeyInput').value = pub;
    if (navigator.clipboard) {
        navigator.clipboard.writeText(priv).then(() => alert("✅ 公鑰已填入，私鑰已自動複製！"));
    }
}

function copyToDecrypt() {
    document.getElementById('decryptInput').value = document.getElementById('encryptOutput').innerText;
}

window.onload = () => {
    document.getElementById('encryptKeyInput').value = localStorage.getItem('rsa_pub') || "";
    document.getElementById('decryptKeyInput').value = localStorage.getItem('rsa_priv') || "";
};