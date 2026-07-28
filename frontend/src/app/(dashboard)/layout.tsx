import type { ReactNode } from "react";

import { ConsoleSidebar } from "@/components/console/sidebar";
import { ConsoleProvider } from "@/lib/store";
import { ToastProvider } from "@/components/ui/toast";

export default function DashboardLayout({
  children,
}: {
  children: ReactNode;
}) {
  return (
    <ConsoleProvider>
      <ToastProvider>
        <div className="flex min-h-screen">
          <ConsoleSidebar />
          <main className="min-w-0 flex-1 px-6 py-8 lg:px-10">
            {children}
          </main>
        </div>
      </ToastProvider>
    </ConsoleProvider>
  );
}
