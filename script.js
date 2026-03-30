/**
 * ---------------------------------------------------------
 * RSA x 114514 惡臭加密器 - 最終整合版 (NSYSU IM Project)
 * ---------------------------------------------------------
 */

// 1. 核心基數定義 (這行絕對不能刪，且必須放在最前面)
const HOMO_BASES = [114514, 514, 114, 14, 11, 5, 4, 1];

/**
 * 核心演算法：將整數 N 拆解為 114514 算式 (已修正無限遞迴)
 */
function getHomo(n) {
    if (n === 0) return "0";
    if (n < 0) return `-( ${getHomo(Math.abs(n))} )`;

    // 終止條件：如果數字就在基礎數組裡，直接回傳
    if (HOMO_BASES.includes(n)) return n.toString();

    // 處理極小數字，防止進入無限遞迴
    if (n < 11) {
        return new Array(n).fill("1").join("+");
    }

    for (let base of HOMO_BASES) {
        // 只有當 n 大於基數且基數大於 1 時才拆解
        if (n >= base && base > 1) { 
            let q = Math.floor(n / base);
            let r = n % base;
            
            let qStr = (q === 1) ? "" : `*(${getHomo(q)})`;
            let res = `${base}${qStr}`;
            
            if (r > 0) res += `+(${getHomo(r)})`;
            return res;
        }
    }
    return new Array(n).fill("1").join("+");
}

/**
 * 自動修補 PEM 格式標籤
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
 * 執行加密邏輯
 */
function doEncrypt() {
    const rawKey = document.getElementById('keyInput').value;
    const text = document.getElementById('plainInput').value;
    
    if (!rawKey || !text) return alert("請輸入金鑰與明文！");

    const pubKey = formatPEM(rawKey, "PUBLIC");
    localStorage.setItem('rsa_key_cache', rawKey); // 儲存金鑰到瀏覽器

    const encryptor = new JSEncrypt();
    encryptor.setPublicKey(pubKey);
    const rsaRes = encryptor.encrypt(text);

    if (!rsaRes) return alert("RSA 加密失敗，請檢查公鑰格式。");

    // 產生 114514 算式密文
    const homoFormula = rsaRes.split('').map(char => {
        return `[${getHomo(char.charCodeAt(0))}]`;
    }).join('+');

    document.getElementById('cipherOutput').innerText = homoFormula;
}

/**
 * 執行解密邏輯 (已修正 Unexpected end of input)
 */
function doDecrypt() {
    const rawKey = document.getElementById('keyInput').value;
    const formula = document.getElementById('cipherOutput').innerText.trim();

    if (!rawKey || !formula || formula.includes("等待")) return alert("請輸入私鑰與有效的密文！");

    const privKey = formatPEM(rawKey, "PRIVATE");
    localStorage.setItem('rsa_key_cache', rawKey);

    try {
        // 清洗算式並還原為 Base64 字串
        const base64 = formula.split('+')
            .map(s => s.trim())
            .filter(s => s.length > 0) // 過濾空字串防止 eval 報錯
            .map(seg => {
                const cleanSeg = seg.replace(/[\[\]]/g, '').trim();
                return String.fromCharCode(eval(cleanSeg));
            }).join('');

        const decryptor = new JSEncrypt();
        decryptor.setPrivateKey(privKey);
        const result = decryptor.decrypt(base64);

        if (result) {
            document.getElementById('plainInput').value = result;
        } else {
            alert("解密失敗！私鑰可能不正確。");
        }
    } catch (e) {
        console.error("解密錯誤:", e);
        alert("解析過程發生錯誤：" + e.message);
    }
}

/**
 * 生成 RSA 測試金鑰對
 */
function generateTestKeys() {
    const crypt = new JSEncrypt({default_key_size: 1024});
    alert("正在生成金鑰，請稍候...");
    const pub = crypt.getPublicKey();
    const priv = crypt.getPrivateKey();
    
    document.getElementById('keyInput').value = pub;
    console.log("--- 測試用私鑰 (請保存以供解密) ---");
    console.log(priv);
    alert("已填入公鑰。私鑰已印在主控台 (F12)，請複製保存！");
}

/**
 * 初始化功能：自動填入與檔案拖放
 */
window.onload = function() {
    const savedKey = localStorage.getItem('rsa_key_cache');
    if (savedKey) document.getElementById('keyInput').value = savedKey;

    const keyArea = document.getElementById('keyInput');
    keyArea.addEventListener('dragover', (e) => {
        e.preventDefault();
        keyArea.style.borderColor = '#e91e63';
    });
    keyArea.addEventListener('drop', (e) => {
        e.preventDefault();
        keyArea.style.borderColor = '#ddd';
        const file = e.dataTransfer.files[0];
        if (file) {
            const reader = new FileReader();
            reader.onload = (ev) => {
                keyArea.value = ev.target.result;
                localStorage.setItem('rsa_key_cache', ev.target.result);
            };
            reader.readAsText(file);
        }
    });
};