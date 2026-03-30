/**
 * ---------------------------------------------------------
 * RSA x 114514 惡臭論證加密器 (v7.0 MagicConch Style)
 * ---------------------------------------------------------
 */

// 1. 核心惡臭基數 (依照論證美感排序)
const HOMO_BASES = [114514, 1919, 810, 114, 514, 114, 51, 4, 1];

/**
 * 核心演算法：參考 MagicConch 的遞迴論證邏輯
 * 將數字 N 轉化為極具「論證感」的算式
 */
function getHomo(n) {
    if (n === 0) return "0";
    if (n < 0) return `-( ${getHomo(Math.abs(n))} )`;
    
    // 如果數字就在基數裡，直接回傳
    if (HOMO_BASES.includes(n)) return n.toString();

    // 尋找最佳基數進行拆解 (n = base * q + r)
    for (let b of HOMO_BASES) {
        if (n > b) {
            let q = Math.floor(n / b);
            let r = n % b;
            
            // 構造算式：base * q + r
            let qStr = (q === 1) ? "" : `*(${getHomo(q)})`;
            let res = `${b}${qStr}`;
            
            if (r > 0) res += `+(${getHomo(r)})`;
            return res;
        }
    }
    // 保底邏輯：如果都沒匹配到，就用 1 湊
    return new Array(n).fill("1").join("+");
}

/**
 * PEM 格式自動補全
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
 * 【加密邏輯】從 encryptInput 讀取，輸出到 encryptOutput
 */
function doEncrypt() {
    const rawKey = document.getElementById('keyInput').value;
    const text = document.getElementById('encryptInput').value;
    
    if (!rawKey || !text) return alert("請輸入金鑰與要加密的明文！");

    const pubKey = formatPEM(rawKey, "PUBLIC");
    localStorage.setItem('rsa_key_cache', rawKey);

    const encryptor = new JSEncrypt();
    encryptor.setPublicKey(pubKey);
    const rsaRes = encryptor.encrypt(text);

    if (!rsaRes) return alert("RSA 加密失敗！");

    // 將 RSA Base64 的每個字元轉為論證算式，並用 [ ] 包起來區隔
    const homoFormula = rsaRes.split('').map(char => {
        return `[${getHomo(char.charCodeAt(0))}]`;
    }).join('+');

    document.getElementById('encryptOutput').innerText = homoFormula;
}

/**
 * 【解密邏輯】從 decryptInput 讀取，輸出到 decryptOutput
 */
function doDecrypt() {
    const rawKey = document.getElementById('keyInput').value;
    const formula = document.getElementById('decryptInput').value.trim();

    if (!rawKey || !formula) return alert("請輸入私鑰與要解密的惡臭密文！");

    const privKey = formatPEM(rawKey, "PRIVATE");
    localStorage.setItem('rsa_key_cache', rawKey);

    try {
        // 解析算式：依照 + 號分割，並過濾掉空值
        const base64Result = formula.split('+')
            .map(s => s.trim())
            .filter(s => s.length > 0)
            .map(seg => {
                // 移除 [ ] 並使用 Function 計算算式值
                const cleanSeg = seg.replace(/[\[\]]/g, '').trim();
                if (!cleanSeg) return "";
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
        console.error("解析失敗:", e);
        alert("算式格式錯誤，無法解析。");
    }
}

/**
 * 生成金鑰並自動複製私鑰
 */
function generateTestKeys() {
    const crypt = new JSEncrypt({default_key_size: 1024});
    alert("正在生成 1024-bit RSA 金鑰對...");
    
    const pub = crypt.getPublicKey();
    const priv = crypt.getPrivateKey();
    
    document.getElementById('keyInput').value = pub;
    
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(priv).then(() => {
            alert("✅ 生成成功！\n1. 公鑰已自動填入。\n2. 私鑰已自動複製到您的剪貼簿。");
        });
    } else {
        console.log("您的私鑰如下：\n", priv);
        alert("公鑰已填入，但自動複製失敗，請按 F12 查看 Console。");
    }
}

window.onload = function() {
    const savedKey = localStorage.getItem('rsa_key_cache');
    if (savedKey) document.getElementById('keyInput').value = savedKey;
};