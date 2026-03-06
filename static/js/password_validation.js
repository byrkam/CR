// ===== PASSWORD VALIDATION + STRENGTH + TOGGLE =====

function validateEmailFormat(email) {
  const pattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  return pattern.test(email);
}


// Toggle password visibility
function togglePassword() {
  const pwdField = document.getElementById("password");
  const toggleIcon = document.querySelector(".toggle-password");
  if (pwdField.type === "password") {
    pwdField.type = "text";
    toggleIcon.textContent = "🙈";
  } else {
    pwdField.type = "password";
    toggleIcon.textContent = "👁️";
  }
}

// Check password strength and rule compliance
function checkPasswordStrength(password) {
  const rules = {
    length: /.{8,}/,
    upper: /[A-Z]/,
    lower: /[a-z]/,
    number: /[0-9]/,
    special: /[!@#$%^&*(),.?":{}|<>]/
  };

  let score = 0;

  for (const [rule, regex] of Object.entries(rules)) {
    const li = document.getElementById(`rule-${rule}`);
    const dot = li ? li.querySelector(".dot") : null;
    if (dot && regex.test(password)) {
      dot.classList.add("valid");
      score++;
    } else if (dot) {
      dot.classList.remove("valid");
    }
  }

  const bar = document.getElementById("strength-bar");
  const label = document.getElementById("strength-label");
  if (!bar || !label) return;

  let strength = "Weak";
  let color = "#d9534f"; // red

  if (score >= 4) {
    strength = "Strong";
    color = "#5cb85c"; // green
  } else if (score === 3) {
    strength = "Medium";
    color = "#f0ad4e"; // orange
  }

  bar.style.width = (score / 5) * 100 + "%";
  bar.style.backgroundColor = color;
  label.textContent = strength;
  label.style.color = color;
}

// ===== EMAIL LIVE VALIDATION =====
document.addEventListener("DOMContentLoaded", () => {
  const emailInput = document.querySelector('input[name="email"]');
  if (!emailInput) return;

  emailInput.addEventListener("input", () => {
    const emailVal = emailInput.value.trim();
    if (!emailVal) {
      emailInput.style.borderColor = "";
      emailInput.style.boxShadow = "";
      return;
    }

    if (validateEmailFormat(emailVal)) {
      emailInput.style.borderColor = "#5cb85c";  // green border
      emailInput.style.boxShadow = "0 0 6px rgba(92,184,92,0.4)";
    } else {
      emailInput.style.borderColor = "#d9534f";  // red border
      emailInput.style.boxShadow = "0 0 6px rgba(217,83,79,0.4)";
    }
  });
});


