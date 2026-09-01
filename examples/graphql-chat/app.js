(function () {
  "use strict";

  var halfLifeMs = 60 * 60 * 1000;

  async function mint() {
    var response = await fetch("/graphql", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query: "query ReplypenChatToken { replypenChatToken { token project baseUrl } }" }),
    });
    var payload = await response.json();
    if (!response.ok || !payload.data) {
      throw new Error(payload.errors && payload.errors[0] ? payload.errors[0].message : "Chat token request failed.");
    }
    return payload.data.replypenChatToken;
  }

  async function refresh() {
    var chat = await mint();
    window.RootCause("update", { token: chat.token });
    window.setTimeout(function () { refresh().catch(showError); }, halfLifeMs);
  }

  async function boot() {
    var chat = await mint();
    var script = document.createElement("script");
    script.async = true;
    script.src = chat.baseUrl.replace(/\/$/, "") + "/chat/widget/v1/loader.js?v=2";
    script.dataset.rcProject = chat.project;
    script.dataset.rcToken = chat.token;
    script.dataset.rcMode = "page";
    script.dataset.rcTarget = "#replypen-chat";
    script.addEventListener("load", function () {
      document.getElementById("status").textContent = "ReplyPen ready.";
      window.setTimeout(function () { refresh().catch(showError); }, halfLifeMs);
    });
    script.addEventListener("error", function () { showError(new Error("The ReplyPen loader could not be loaded.")); });
    document.head.appendChild(script);
  }

  function showError(error) {
    document.getElementById("status").textContent = error.message;
    console.error(error);
  }

  boot().catch(showError);
})();
