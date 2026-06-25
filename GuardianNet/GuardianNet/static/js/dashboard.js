document.addEventListener("DOMContentLoaded", () => {
  const modal = document.getElementById("processing-modal");
  const title = document.getElementById("processing-title");
  const body = document.getElementById("processing-body");
  const steps = document.getElementById("processing-steps");

  function showProcessing(form) {
    if (!modal || !form.dataset.processingTitle) return;
    title.textContent = form.dataset.processingTitle;
    body.textContent = form.dataset.processingBody || "İşlem birkaç saniye sürebilir.";
    steps.innerHTML = "";
    (form.dataset.processingSteps || "")
      .split("|")
      .filter(Boolean)
      .forEach((text) => {
        const item = document.createElement("li");
        item.textContent = text;
        steps.appendChild(item);
      });
    modal.hidden = false;
  }

  document.querySelectorAll("form").forEach((form) => {
    form.addEventListener("submit", () => {
      showProcessing(form);
      const button = form.querySelector("button[type='submit'],button:not([type])");
      if (button) {
        button.disabled = true;
        button.textContent = "İşleniyor...";
      }
    });
  });
});
