/**
 * ---------------------------------------------------------
 * RSA x 114514 惡臭加密器 (v5.0 自動化增強版)
 * 專為 NSYSU IM 專案打造
 * ---------------------------------------------------------
 */

// 1. 核心惡臭基數
const HOMO_BASES = [114514, 514, 114, 14, 11, 5, 4, 1];

/**
 * 貪婪湊數法：產生 11451411451... 的視覺效果
 */
function getHomo(n) {
    if (n === 0) return "0";
    let temp = n;
    let res = [];
    for (let b of HOMO_BASES) {
        while (temp >= b) {
            res.push(b);
            temp -= b;
        }
    }
    return res.join('+');
}

/**
 * PEM 格式自動修正
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
 * 加密：明文 -> 114514 數字牆
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

    const homoFormula = rsaRes.split('').map(char => {
        return getHomo(char.charCodeAt(0));
    }).join(' ');

    document.getElementById('cipherOutput').innerText = homoFormula;
}

/**
 * 解密：數字牆還原 (含空值過濾)
 */
function doDecrypt() {
    const rawKey = document.getElementById('keyInput').value;
    const formula = document.getElementById('cipherOutput').innerText.trim();

    if (!rawKey || !formula || formula.includes("等待")) return alert("請輸入私鑰與有效的密文！");

    const privKey = formatPEM(rawKey, "PRIVATE");
    localStorage.setItem('rsa_key_cache', rawKey);

    try {
        const base64Result = formula.split(/\s+/).map(charSeg => {
            if (!charSeg.trim()) return "";
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
        alert("解析失敗，請確認密文格式。");
    }
}

/**
 * 🚀 重點功能：生成金鑰並「自動複製私鑰」
 */
function generateTestKeys() {
    const crypt = new JSEncrypt({default_key_size: 1024});
    
    // 提示使用者正在處理，因為 1024-bit 需要一點計算時間
    alert("正在生成 RSA 金鑰對（1024-bit），請稍候...");
    
    const pub = crypt.getPublicKey();
    const priv = crypt.getPrivateKey();
    
    // 1. 將公鑰填入輸入框
    document.getElementById('keyInput').value = pub;
    
    // 2. 使用 Clipboard API 自動複製私鑰
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(priv).then(() => {
            alert("✅ 金鑰生成成功！\n1. 公鑰已自動填入輸入框。\n2. 私鑰已自動複製到您的剪貼簿，請妥善保存。");
        }).catch(err => {
            console.error("複製失敗:", err);
            console.log("您的私鑰如下：\n", priv);
            alert("公鑰已填入，但自動複製私鑰失敗，請按 F12 在 Console 複製。");
        });
    } else {
        // 相容性回退方案
        console.log("您的私鑰如下：\n", priv);
        alert("您的瀏覽器不支援自動複製，請按 F12 在 Console 查看私鑰。");
    }
}

/**
 * 初始化載入與拖放
 */
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