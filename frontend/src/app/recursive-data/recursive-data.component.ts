import { CommonModule } from '@angular/common';
import { Component, Input } from '@angular/core';

@Component({
    selector: 'app-recursive-data',
    standalone: true,
    imports: [CommonModule],
    templateUrl: './recursive-data.component.html',
    styleUrl: './recursive-data.component.css'
})
export class ResursiveDataComponent {
    @Input() data: any;

    isObject(value: any): boolean {
        return value && typeof value === 'object' && !Array.isArray(value);
    }

    isArray(value: any): boolean {
        return Array.isArray(value);
    }

    asKeyValue(obj: any): Record<string, unknown> | null {
        return this.isObject(obj) ? (obj as Record<string, unknown>) : null;
    }
}
