/**
 * Social Hub Components Index
 *
 * This file exports all social components wrapped with error boundaries
 * for better fault tolerance and user experience.
 */

import { withSocialErrorBoundary, SocialErrorBoundary } from './SocialErrorBoundary';

// Import base components
import MessagesTabBase from './MessagesTab';
import ThreadViewDialogBase from './ThreadViewDialog';
import MessageSearchDialogBase from './MessageSearchDialog';
import GroupSettingsDialogBase from './GroupSettingsDialog';
import EmojiPickerBase from './EmojiPicker';
import PollCreatorBase from './PollCreator';
import UserSearchTabBase from './UserSearchTab';
import FriendRequestsTabBase from './FriendRequestsTab';
import FriendsListTabBase from './FriendsListTab';

// Export error-boundary wrapped versions as defaults
export const MessagesTab = withSocialErrorBoundary(MessagesTabBase, 'MessagesTab');
export const ThreadViewDialog = withSocialErrorBoundary(ThreadViewDialogBase, 'ThreadViewDialog');
export const MessageSearchDialog = withSocialErrorBoundary(MessageSearchDialogBase, 'MessageSearchDialog');
export const GroupSettingsDialog = withSocialErrorBoundary(GroupSettingsDialogBase, 'GroupSettingsDialog');
export const EmojiPicker = withSocialErrorBoundary(EmojiPickerBase, 'EmojiPicker');
export const PollCreator = withSocialErrorBoundary(PollCreatorBase, 'PollCreator');
export const UserSearchTab = withSocialErrorBoundary(UserSearchTabBase, 'UserSearchTab');
export const FriendRequestsTab = withSocialErrorBoundary(FriendRequestsTabBase, 'FriendRequestsTab');
export const FriendsListTab = withSocialErrorBoundary(FriendsListTabBase, 'FriendsListTab');

// Also export unwrapped versions for cases where custom error handling is needed
export {
  MessagesTabBase,
  ThreadViewDialogBase,
  MessageSearchDialogBase,
  GroupSettingsDialogBase,
  EmojiPickerBase,
  PollCreatorBase,
  UserSearchTabBase,
  FriendRequestsTabBase,
  FriendsListTabBase,
};

// Re-export utilities
export { SocialErrorBoundary, withSocialErrorBoundary };
export { StatusSelector } from './StatusSelector';
export { PresenceIndicator } from './PresenceIndicator';
export type { PresenceStatus } from './PresenceIndicator';

// New components
export { RichTextToolbar } from './RichTextToolbar';
export { GlobalSearchDialog } from './GlobalSearchDialog';
export { default as ShareToConversationDialog } from './ShareToConversationDialog';
