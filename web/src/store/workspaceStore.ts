/**
 * Zustand store for workspace state.
 *
 * Manages current workspace, user preferences, and global UI state.
 */

import { create } from 'zustand';
import { persist } from 'zustand/middleware';

interface WorkspaceState {
  /** Current workspace ID */
  workspaceId: string | null;
  /** User display name */
  userName: string | null;
  /** Dark mode preference */
  darkMode: boolean;
  /** Sidebar collapsed */
  sidebarCollapsed: boolean;

  // Actions
  setWorkspace: (id: string) => void;
  setUser: (name: string) => void;
  toggleDarkMode: () => void;
  toggleSidebar: () => void;
}

export const useWorkspaceStore = create<WorkspaceState>()(
  persist(
    (set) => ({
      workspaceId: null,
      userName: null,
      darkMode: false,
      sidebarCollapsed: false,

      setWorkspace: (id) => set({ workspaceId: id }),
      setUser: (name) => set({ userName: name }),
      toggleDarkMode: () => set((s) => ({ darkMode: !s.darkMode })),
      toggleSidebar: () => set((s) => ({ sidebarCollapsed: !s.sidebarCollapsed })),
    }),
    { name: 'querysense-workspace' },
  ),
);
