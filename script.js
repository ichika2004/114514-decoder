/**
 * 114514 核心演算法：將整數 N 拆解為由指定基數組成的算式
 */
const HOMO_BASES = [114514, 514, 114, 14, 11, 5, 4, 1];

function getHomo(n) {
    if (n === 0) return "0";
    if (n < 0) return `-( ${getHomo(Math.abs(n))} )`;
    
    for (let base of HOMO_BASES) {
        if (n >= base) {
            let q = Math.floor(n / base);
            let r = n % base;
            let res = "";
            
            // 遞迴建構算式
            if (q === 1) res = `${base}`;
            else res = `${base}*(${getHomo(q)})`;
            
            if (r > 0) res += `+(${getHomo(r)})`;
            return res;
        }
    }
}

/**
 * 執行加密：RSA 加密 -> 轉 ASCII -> 轉 114514 算式
 */
function doEncrypt() {
    const pubKey = document.getElementById('keyInput').value;
    const text = document.getElementById('plainInput').value;
    
    if (!pubKey || !text) {
        alert("請輸入金鑰與明文！");
        return;
    }

    const encryptor = new JSEncrypt();
    encryptor.setPublicKey(pubKey);
    const rsaRes = encryptor.encrypt(text);

    if (!rsaRes) {
        alert("RSA 加密失敗，請檢查公鑰格式是否正確（需包含 BEGIN/END PUBLIC KEY）。");
        return;
    }

    // 逐字元轉換為算式區段
    let homoFormula = rsaRes.split('').map(char => {
        return `[${getHomo(char.charCodeAt(0))}]`;
    }).join('+');

    document.getElementById('cipherOutput').innerText = homoFormula;
}

/**
 * 執行解密：解析算式 -> 還原 Base64 -> RSA 解密
 */
function doDecrypt() {
    const privKey = document.getElementById('keyInput').value;
    const formula = document.getElementById('cipherOutput').innerText;

    if (!privKey || formula.includes("等待")) {
        alert("請輸入私鑰與有效的算式密文！");
        return;
    }

    try {
        // 解析算式區段並計算結果 (還原為 ASCII 字元)
        const base64 = formula.split('+').map(seg => {
            const cleanSeg = seg.replace(/\[|\]/g, '');
            // 在此處使用 eval 是因為算式完全由我們受控的 HOMO_BASES 組成
            return String.fromCharCode(eval(cleanSeg));
        }).join('');

        const decryptor = new JSEncrypt();
        decryptor.setPrivateKey(privKey);
        const result = decryptor.decrypt(base64);

        if (result) {
            document.getElementById('plainInput').value = result;
        } else {
            alert("解密失敗！可能是私鑰不匹配。");
        }
    } catch (e) {
        alert("解析算式時發生錯誤：" + e.message);
    }
}

/**
 * 輔助功能：生成測試用的 RSA 金鑰對
 */
function generateTestKeys() {
    const crypt = new JSEncrypt({default_key_size: 1024});
    alert("正在生成金鑰，請稍候...");
    const pub = crypt.getPublicKey();
    const priv = crypt.getPrivateKey();
    
    document.getElementById('keyInput').value = pub;
    console.log("--- 測試用私鑰 (請妥善保存以供解密) ---");
    console.log(priv);
    alert("已在上方填入公鑰。私鑰已印在瀏覽器主控台 (F12)，請複製保存以供測試解密。");
}