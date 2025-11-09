import type { Result } from './api.utils';

export interface SettingsPermissions {
  can_access_settings: boolean;
}

export class Permissions {
  static async checkSettingsAccess(): Promise<Result<SettingsPermissions>> {
    const response = await fetch('/internal/permissions/settings', {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json'
      }
    });

    if (!response.ok) {
      return {
        status: 'ERROR',
        message: `Failed to check settings permissions: ${response.statusText}`
      };
    }

    const data = await response.json();
    return {
      status: 'OK',
      message: '',
      data,
      errors: []
    };
  }
}
