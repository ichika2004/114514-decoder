/**
 * ---------------------------------------------------------
 * RSA x 114514 惡臭加密器 - 核心邏輯 (NSYSU IM Project)
 * ---------------------------------------------------------
 */

// 114514 核心基數
const HOMO_BASES = [114514, 514, 114, 14, 11, 5, 4, 1];

/**
 * 114514 遞迴論證演算法：將整數 N 轉化為算式字串
 */
/**
 * 修正後的 114514 遞迴演算法
 */
function getHomo(n) {
    // 終止條件 1：如果是 0
    if (n === 0) return "0";
    
    // 終止條件 2：如果數字本身就在基礎數組裡，直接回傳字串，防止無限遞迴
    if (HOMO_BASES.includes(n)) return n.toString();
    
    // 處理負數
    if (n < 0) return `-( ${getHomo(Math.abs(n))} )`;
    
    for (let base of HOMO_BASES) {
        // 只有當 n 大於該基數時才進行拆解
        if (n > base) { 
            let q = Math.floor(n / base);
            let r = n % base;
            let res = "";
            
            // 如果商數是 1，就不用再遞迴商數了
            if (q === 1) {
                res = `${base}`;
            } else {
                // 如果基數是 1，商數就是 n 自己，不能遞迴，直接轉字串
                let qStr = (base === 1) ? q.toString() : `(${getHomo(q)})`;
                res = `${base}*${qStr}`;
            }
            
            // 處理餘數
            if (r > 0) res += `+(${getHomo(r)})`;
            return res;
        }
    }
    return n.toString();
}

/**
 * 自動修補 PEM 格式：如果使用者沒貼標籤，自動補上
 */
function formatPEM(rawKey, type = "PUBLIC") {
    let cleanKey = rawKey.trim();
    if (!cleanKey) return "";
    if (!cleanKey.includes("-----BEGIN")) {
        // 補上標準標籤，RSA 才能正常讀取
        return `-----BEGIN ${type} KEY-----\n${cleanKey}\n-----END ${type} KEY-----`;
    }
    return cleanKey;
}

/**
 * 執行加密：明文 -> RSA -> Base64 -> 114514 算式
 */
function doEncrypt() {
    const rawKey = document.getElementById('keyInput').value;
    const text = document.getElementById('plainInput').value;
    
    if (!rawKey || !text) return alert("請輸入金鑰與明文！");

    // 自動格式化並儲存金鑰到瀏覽器
    const pubKey = formatPEM(rawKey, "PUBLIC");
    localStorage.setItem('rsa_key_cache', rawKey);

    const encryptor = new JSEncrypt();
    encryptor.setPublicKey(pubKey);
    const rsaRes = encryptor.encrypt(text); // 得到 Base64

    if (!rsaRes) return alert("RSA 加密失敗，請檢查公鑰格式。");

    // 將 Base64 每個字元轉為 ASCII 碼，再轉為 [算式]
    const homoFormula = rsaRes.split('').map(char => {
        return `[${getHomo(char.charCodeAt(0))}]`;
    }).join('+');

    document.getElementById('cipherOutput').innerText = homoFormula;
}

/**
 * 執行解密：114514 算式 -> 還原 Base64 -> RSA -> 明文
 */
function doDecrypt() {
    const rawKey = document.getElementById('keyInput').value;
    const formula = document.getElementById('cipherOutput').innerText;

    if (!rawKey || formula.includes("等待")) return alert("請輸入私鑰與有效的算式密文！");

    const privKey = formatPEM(rawKey, "PRIVATE");
    localStorage.setItem('rsa_key_cache', rawKey);

    try {
        // 解析算式區段並還原為字元
        const base64 = formula.split('+').map(seg => {
            const cleanSeg = seg.replace(/\[|\]/g, '');
            // 注意：eval 在此僅用於計算我們受控生成的 114514 算式
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
        alert("算式解析錯誤：" + e.message);
    }
}

/**
 * 生成測試金鑰對
 */
function generateTestKeys() {
    const crypt = new JSEncrypt({default_key_size: 1024});
    alert("正在生成金鑰（1024-bit），請稍候...");
    const pub = crypt.getPublicKey();
    const priv = crypt.getPrivateKey();
    
    document.getElementById('keyInput').value = pub;
    console.log("--- 你的測試用私鑰 (請保存) ---");
    console.log(priv);
    alert("公鑰已填入。私鑰已印在 Console (F12)，請複製保存！");
}

/**
 * 初始化：載入緩存與拖放功能
 */
window.onload = function() {
    // 1. 自動載入上次使用的金鑰
    const savedKey = localStorage.getItem('rsa_key_cache');
    if (savedKey) {
        document.getElementById('keyInput').value = savedKey;
    }

    // 2. 拖放檔案功能
    const keyArea = document.getElementById('keyInput');
    
    keyArea.addEventListener('dragover', (e) => {
        e.preventDefault();
        keyArea.style.borderColor = '#e91e63';
        keyArea.style.background = '#fff0f5';
    });

    keyArea.addEventListener('dragleave', () => {
        keyArea.style.borderColor = '#ddd';
        keyArea.style.background = '#fff';
    });

    keyArea.addEventListener('drop', (e) => {
        e.preventDefault();
        keyArea.style.borderColor = '#ddd';
        keyArea.style.background = '#fff';
        
        const file = e.dataTransfer.files[0];
        if (file) {
            const reader = new FileReader();
            reader.onload = (event) => {
                keyArea.value = event.target.result;
                localStorage.setItem('rsa_key_cache', event.target.result);
            };
            reader.readAsText(file);
        }
    });
};