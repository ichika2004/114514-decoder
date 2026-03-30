/**
 * ---------------------------------------------------------
 * RSA x 114514 惡臭加密器 (v4.0 惡臭外溢版)
 * 專為 NSYSU IM 打造：解決解析錯誤 & 強化視覺效果
 * ---------------------------------------------------------
 */

// 1. 核心惡臭基數 (按優先權排序)
const HOMO_BASES = [114514, 514, 114, 14, 11, 5, 4, 1];

/**
 * 貪婪湊數法：將數字 N 轉化為純粹的 114514 數字堆疊
 * 例如：65 會變成 "14+14+14+14+5+4"
 */
function getHomo(n) {
    if (n === 0) return "0";
    let temp = n;
    let res = [];
    
    // 遍歷基數，能塞多少就塞多少，產生 11451411451... 的視覺感
    for (let b of HOMO_BASES) {
        while (temp >= b) {
            res.push(b);
            temp -= b;
        }
    }
    // 使用 + 連接，看起來會非常像一串連續數字
    return res.join('+');
}

/**
 * 自動修正 PEM 標籤
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
 * 加密：將明文轉為一連串「惡臭算式」
 */
function doEncrypt() {
    const rawKey = document.getElementById('keyInput').value;
    const text = document.getElementById('plainInput').value;
    
    if (!rawKey || !text) return alert("請輸入金鑰與明文！");

    const pubKey = formatPEM(rawKey, "PUBLIC");
    localStorage.setItem('rsa_key_cache', rawKey);

    const encryptor = new JSEncrypt();
    encryptor.setPublicKey(pubKey);
    const rsaRes = encryptor.encrypt(text);

    if (!rsaRes) return alert("RSA 加密失敗！");

    // 將每個 ASCII 字元轉為一組算式，並用「空白」區隔字元
    // 這樣視覺上會像是一整塊 114514 數字牆
    const homoFormula = rsaRes.split('').map(char => {
        return getHomo(char.charCodeAt(0));
    }).join(' '); // 這裡用空白區隔每個字元，避免 + 號過多導致解析混亂

    document.getElementById('cipherOutput').innerText = homoFormula;
}

/**
 * 解密：將數字牆還原 (修正 Unexpected end of input)
 */
function doDecrypt() {
    const rawKey = document.getElementById('keyInput').value;
    const formula = document.getElementById('cipherOutput').innerText.trim();

    if (!rawKey || !formula || formula.includes("等待")) return alert("請輸入私鑰與有效的密文！");

    const privKey = formatPEM(rawKey, "PRIVATE");
    localStorage.setItem('rsa_key_cache', rawKey);

    try {
        // 先按空白切分字元，再按加號計算數值
        const base64Result = formula.split(/\s+/).map(charSeg => {
            if (!charSeg.trim()) return "";
            
            // 將 "514+114+1" 這種算式安全地加總
            const charCode = charSeg.split('+')
                .filter(num => num.trim().length > 0)
                .reduce((sum, num) => sum + parseInt(num, 10), 0);
                
            return String.fromCharCode(charCode);
        }).join('');

        const decryptor = new JSEncrypt();
        decryptor.setPrivateKey(privKey);
        const result = decryptor.decrypt(base64Result);

        if (result) {
            document.getElementById('plainInput').value = result;
        } else {
            alert("解密失敗！私鑰可能不正確。");
        }
    } catch (e) {
        console.error("解密錯誤:", e);
        alert("解析失敗，請確認密文格式是否正確。");
    }
}

/**
 * 其他功能保持不變
 */
function generateTestKeys() {
    const crypt = new JSEncrypt({default_key_size: 1024});
    alert("正在生成金鑰...");
    const pub = crypt.getPublicKey();
    const priv = crypt.getPrivateKey();
    document.getElementById('keyInput').value = pub;
    console.log("--- 私鑰 ---");
    console.log(priv);
    alert("公鑰已填入。私鑰已印在 Console (F12)。");
}

window.onload = function() {
    const savedKey = localStorage.getItem('rsa_key_cache');
    if (savedKey) document.getElementById('keyInput').value = savedKey;

    const keyArea = document.getElementById('keyInput');
    keyArea.addEventListener('dragover', (e) => e.preventDefault());
    keyArea.addEventListener('drop', (e) => {
        e.preventDefault();
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