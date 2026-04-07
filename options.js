const DEFAULTS = {
  resolver: "cloudflare",
  customResolver: "",
  nextdnsId: "",
  autoLookup: true,
  traceProbe: false,
};

const TRACE_ORIGINS = { origins: ["https://*/*"] };

function $(id) { return document.getElementById(id); }

async function load() {
  const s = await chrome.storage.local.get(DEFAULTS);
  for (const r of document.querySelectorAll('input[name="resolver"]')) {
    r.checked = r.value === s.resolver;
  }
  $("customResolver").value = s.customResolver;
  $("customResolver").disabled = s.resolver !== "custom";
  $("nextdnsId").value = s.nextdnsId;
  $("nextdnsId").disabled = s.resolver !== "nextdns";
  $("autoLookup").checked = !!s.autoLookup;
  $("traceProbe").checked = !!s.traceProbe;
  await updatePermStatus();
}

async function updatePermStatus() {
  const has = await chrome.permissions.contains(TRACE_ORIGINS).catch(() => false);
  const el = $("permStatus");
  if ($("traceProbe").checked && !has) {
    el.textContent = "Permission not yet granted — toggling on will prompt.";
  } else if (has) {
    el.textContent = "Host permission granted.";
  } else {
    el.textContent = "";
  }
}

function toast(msg) {
  const el = $("saved");
  el.textContent = msg;
  el.classList.add("show");
  setTimeout(() => el.classList.remove("show"), 1200);
}

async function save(partial) {
  await chrome.storage.local.set(partial);
  toast("Saved");
}

document.addEventListener("DOMContentLoaded", () => {
  load();

  for (const r of document.querySelectorAll('input[name="resolver"]')) {
    r.addEventListener("change", async () => {
      const value = r.value;
      $("customResolver").disabled = value !== "custom";
      $("nextdnsId").disabled = value !== "nextdns";
      await save({ resolver: value });
    });
  }
  $("customResolver").addEventListener("change", async (e) => {
    const v = e.target.value.trim();
    if (v && !/^https:\/\//i.test(v)) {
      toast("Resolver must be HTTPS");
      return;
    }
    await save({ customResolver: v });
  });
  $("nextdnsId").addEventListener("change", async (e) => {
    const v = e.target.value.trim();
    if (v && !/^[A-Za-z0-9]+$/.test(v)) {
      toast("Profile ID should be letters and numbers only");
      return;
    }
    await save({ nextdnsId: v });
  });
  $("autoLookup").addEventListener("change", async (e) => {
    await save({ autoLookup: e.target.checked });
  });
  $("traceProbe").addEventListener("change", async (e) => {
    if (e.target.checked) {
      const granted = await chrome.permissions.request(TRACE_ORIGINS).catch(() => false);
      if (!granted) {
        e.target.checked = false;
        toast("Permission denied");
        return;
      }
    } else {
      await chrome.permissions.remove(TRACE_ORIGINS).catch(() => {});
    }
    await save({ traceProbe: e.target.checked });
    await updatePermStatus();
  });
  $("clearCache").addEventListener("click", () => {
    chrome.runtime.sendMessage({ type: "clearCache" }, () => {
      if (chrome.runtime.lastError) toast("Error clearing cache");
      else toast("Cache cleared");
    });
  });
});
