/**
 * ---------------------------------------------------------
 * RSA x 114514 惡臭論證器 (完全比照 MagicConch 演算法)
 * ---------------------------------------------------------
 */

// 1. 精確的惡臭基數序列
const HOMO_BASES = [114514, 1919, 810, 114, 514, 191, 81, 14, 51, 4, 1];

/**
 * 核心論證演算法：比照 lab.magiconch.com/homo/
 * 採用 n = base * q + r 的遞迴拆解
 */
function getHomo(n) {
    if (n === 0) return "0";
    if (n < 0) return `-( ${getHomo(Math.abs(n))} )`;
    
    // 如果數字就在基數列表裡，直接回傳
    if (HOMO_BASES.includes(n)) return n.toString();

    // 尋找最大的基數 b，使得 n > b
    for (let b of HOMO_BASES) {
        if (n > b) {
            // 特殊處理：當基數為 1 時，直接用加法湊齊，防止 1*n 的無限遞迴
            if (b === 1) {
                return new Array(n).fill("1").join("+");
            }

            let q = Math.floor(n / b);
            let r = n % b;
            
            // 遞迴公式：(b*q+r)
            let res = `(${b}*${getHomo(q)})`;
            if (r > 0) res += `+(${getHomo(r)})`;
            return res;
        }
    }
    return n.toString();
}

/**
 * 加密：RSA -> 每個字元獨立進行「論證」
 */
function doEncrypt() {
    const pubKeyRaw = document.getElementById('encryptKeyInput').value;
    const text = document.getElementById('encryptInput').value;
    
    if (!pubKeyRaw || !text) return alert("請輸入公鑰與明文！");

    const pubKey = formatPEM(pubKeyRaw, "PUBLIC");
    const encryptor = new JSEncrypt();
    encryptor.setPublicKey(pubKey);
    const rsaRes = encryptor.encrypt(text);

    if (!rsaRes) return alert("RSA 加密失敗！");

    // 為了視覺上的「11451411451~」，每個字元的算式都包在 [] 內，並緊密相連
    const homoFormula = rsaRes.split('').map(char => {
        return `[${getHomo(char.charCodeAt(0))}]`;
    }).join('');

    document.getElementById('encryptOutput').innerText = homoFormula;
    localStorage.setItem('rsa_pub_cache', pubKeyRaw);
}

/**
 * 解密：使用正規表達式抓取每個論證塊
 */
function doDecrypt() {
    const privKeyRaw = document.getElementById('decryptKeyInput').value;
    const formula = document.getElementById('decryptInput').value.trim();

    if (!privKeyRaw || !formula) return alert("請輸入私鑰與惡臭密文！");

    const privKey = formatPEM(privKeyRaw, "PRIVATE");
    localStorage.setItem('rsa_priv_cache', privKeyRaw);

    try {
        // 使用 Regex 抓取 [ ... ] 內容，這能處理複雜的括號嵌套
        const segments = formula.match(/\[(.*?)\]/g);
        if (!segments) throw new Error("找不到有效的惡臭論證塊");

        const base64Result = segments.map(seg => {
            const cleanSeg = seg.slice(1, -1); // 移除 [ ]
            // 使用 new Function 計算算式值，這比 eval 穩定
            const val = new Function(`return ${cleanSeg}`)();
            return String.fromCharCode(val);
        }).join('');

        const decryptor = new JSEncrypt();
        decryptor.setPrivateKey(privKey);
        const result = decryptor.decrypt(base64Result);

        if (result) {
            document.getElementById('decryptOutput').innerText = result;
        } else {
            alert("解密失敗！金鑰不匹配或密文損壞。");
        }
    } catch (e) {
        console.error(e);
        alert("算式解析失敗：格式不正確或包含非法字元。");
    }
}

// 輔助函式 (自動修正 PEM、金鑰生成、複製功能等)
function formatPEM(rawKey, type) {
    let clean = (rawKey || "").trim();
    if (!clean.includes("-----BEGIN")) {
        return `-----BEGIN ${type} KEY-----\n${clean}\n-----END ${type} KEY-----`;
    }
    return clean;
}

function copyToDecrypt() {
    const res = document.getElementById('encryptOutput').innerText;
    if (res && !res.includes("等待")) document.getElementById('decryptInput').value = res;
}

function generateTestKeys() {
    const crypt = new JSEncrypt({default_key_size: 1024});
    alert("正在生成金鑰...");
    const pub = crypt.getPublicKey();
    const priv = crypt.getPrivateKey();
    document.getElementById('encryptKeyInput').value = pub;
    if (navigator.clipboard) {
        navigator.clipboard.writeText(priv).then(() => alert("✅ 公鑰已填入，私鑰已複製！"));
    }
}

window.onload = function() {
    document.getElementById('encryptKeyInput').value = localStorage.getItem('rsa_pub_cache') || "";
    document.getElementById('decryptKeyInput').value = localStorage.getItem('rsa_priv_cache') || "";
};