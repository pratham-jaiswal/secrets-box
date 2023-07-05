let regPasswordField = document.getElementById("reg-password");
let regEmailField = document.getElementById("reg-email");
let passwordConditions = document.getElementById("passwordConditions");
let loginEmailField = document.getElementById("log-email");
let loginPasswordField = document.getElementById("log-password");
let shareField = document.getElementById("share-secret");

if(regPasswordField){
    regPasswordField.addEventListener("input", function () {
        let password = regPasswordField.value;
        let email = regEmailField.value;
        let minCharCondition = document.getElementById("minCharCondition");
        let alphabetCondition = document.getElementById("alphabetCondition");
        let numberCondition = document.getElementById("numberCondition");
        let symbolCondition = document.getElementById("symbolCondition");
        let spaceCondition = document.getElementById("spaceCondition");
        let registerBtn = document.getElementById("registerBtn");
    
        if (password.length >= 8)
        {
            minCharCondition.style.color = "green";
            minCharCondition.innerHTML = '<i class="fa-regular fa-circle-check"></i> Shoule be atlast 8 characters';
        } 
        else
        {
            minCharCondition.style.color = "red";
            minCharCondition.innerHTML = '<i class="fa-regular fa-circle-xmark"></i> Shoule be atlast 8 characters';
        }
    
        if (/[a-zA-Z]/.test(password))
        {
            alphabetCondition.style.color = "green";
            alphabetCondition.innerHTML = '<i class="fa-regular fa-circle-check"></i> Should contain at least one alphabet';
        } 
        else {
            alphabetCondition.style.color = "red";
            alphabetCondition.innerHTML = '<i class="fa-regular fa-circle-xmark"></i> Should contain at least one alphabet';
        }
    
        if (/\d/.test(password))
        {
            numberCondition.style.color = "green";
            numberCondition.innerHTML = '<i class="fa-regular fa-circle-check"></i> Should contain at least one number';
        } 
        else {
            numberCondition.style.color = "red";
            numberCondition.innerHTML = '<i class="fa-regular fa-circle-xmark"></i> Should contain at least one number';
        }
    
        if (/[!@#$%^&*(),.?":{}|<>]/.test(password))
        {
            symbolCondition.style.color = "green";
            symbolCondition.innerHTML = '<i class="fa-regular fa-circle-check"></i> Should contain at least one symbol';
        } 
        else {
            symbolCondition.style.color = "red";
            symbolCondition.innerHTML = '<i class="fa-regular fa-circle-xmark"></i> Should contain at least one symbol';
        }
    
        if (password.includes(" ")) {
            spaceCondition.style.color = "red";
            spaceCondition.innerHTML = '<i class="fa-regular fa-circle-xmark"></i> Should not contain any spaces';
        }
        else {
            spaceCondition.style.color = "green";
            spaceCondition.innerHTML = '<i class="fa-regular fa-circle-check"></i> Should not contain any spaces';
        }
    
        if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && password.length >= 8 && /[a-zA-Z]/.test(password) && /\d/.test(password) && /[!@#$%^&*(),.?":{}|<>]/.test(password) && !password.includes(" "))
        {
            passwordConditions.style.display = "none";
            registerBtn.disabled = false;
        } 
        else {
            passwordConditions.style.display = "flex";
            registerBtn.disabled = true;
        }
    });
}

if(regEmailField){
    regEmailField.addEventListener("input", function () {
        let password = regPasswordField.value;
        let email = regEmailField.value;
        let registerBtn = document.getElementById("registerBtn");
    
        if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && password.length >= 8 && /[a-zA-Z]/.test(password) && /\d/.test(password) && /[!@#$%^&*(),.?":{}|<>]/.test(password) && !password.includes(" "))
        {
            registerBtn.disabled = false;
        } 
        else {
            registerBtn.disabled = true;
        }
    });
}

if(loginPasswordField){
    loginPasswordField.addEventListener("input", function () {
        let password = loginPasswordField.value;
        let email = loginEmailField.value;
        let loginBtn = document.getElementById("loginBtn");
    
        if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && password.length >= 8)
        {
            loginBtn.disabled = false;
        } 
        else {
            loginBtn.disabled = true;
        }
    });
}

if(loginEmailField){
    loginEmailField.addEventListener("input", function () {
        let password = loginPasswordField.value;
        let email = loginEmailField.value;
        let loginBtn = document.getElementById("loginBtn");
    
        if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && password.length >= 8)
        {
            loginBtn.disabled = false;
        } 
        else {
            loginBtn.disabled = true;
        }
    });
}

if(shareField){
    shareField.addEventListener("input", function () {
        let secret = shareField.value;
        console.log(secret);
        let shareBtn = document.getElementById("shareBtn");
        if (secret.length >= 3){
            shareBtn.disabled = false;
        }
        else{
            shareBtn.disabled = true;
        }
    });
}