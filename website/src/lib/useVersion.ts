"use client";

import { useState, useEffect } from "react";

export function useVersion() {
  const [version, setVersion] = useState({
    version: "",
    codename: "",
    releaseDate: "",
    channel: "",
  });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch("/api/version")
      .then((res) => res.json())
      .then((data) => {
        setVersion(data);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  return { ...version, loading };
}
