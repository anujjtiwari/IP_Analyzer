import { Component, OnInit } from '@angular/core';
import {
	ReactiveFormsModule,
	FormBuilder,
	FormGroup,
	Validators,
} from '@angular/forms';
import { Router } from '@angular/router';
import { CommonModule } from '@angular/common';
import { FormService } from '../form.service';
import { HeaderComponent } from '../header/header.component';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { LoaderComponent } from '../loader/loader.component';

@Component({
	selector: 'app-home',
	standalone: true,
	imports: [
		ReactiveFormsModule,
		CommonModule,
		HeaderComponent,
		MatSnackBarModule,
		LoaderComponent,
	],
	templateUrl: './home.component.html',
	styleUrl: './home.component.css',
})
export class HomeComponent implements OnInit {
	homeForm!: FormGroup;
	isLoading = false;
	// userName!: string;
	options = [
		{
			name: 'geoLocation',
			label: 'Geo Location',
			tooltip: 'Get the geo location of IP or Domain',
		},
		{
			name: 'blackList',
			label: 'Block List',
			tooltip: 'Get the Block Lists where the IP or Domain has been blocked.',
		},
		{
			name: 'portScan',
			label: 'Port Scan',
			tooltip:
				'Get the open, closed, filtered and unfiltered ports of IP or Domain.',
		},
		{
			name: 'searchDatabase',
			label: 'Use Cached Entries',
			tooltip: `Prefer Cached Entries over fresh API calls to retrieve information. 
		You can also check "Geo Location", "Block List" and/or "Community Reports" 
		along with this option. These options will work as filters to the retrieved information.`,
		},
		{
			name: 'reports',
			label: 'Community Reports',
			tooltip: `Get the community reports for given IP or Domain`,
		},
		{
			name: 'dns_history',
			label: 'DNS History',
			tooltip: `Get the DNS History of a Domain`,
		},
	];

	constructor(
		private fb: FormBuilder,
		private router: Router,
		private formService: FormService,
		private snackBar: MatSnackBar
	) { }

	ngOnInit(): void {
		this.homeForm = this.fb.group({
			ip_domain: ['', Validators.required],
			geoLocation: [false],
			blackList: [false],
			portScan: [false],
			searchDatabase: [false],
			reports: [false],
			dns_history: [false],
		});
	}

	onSubmit() {
		this.isLoading = true;
		if (this.homeForm.valid) {
			this.formService.compute_results(this.homeForm.value).subscribe({
				next: (response) => {
					console.log(`${response}.`);
					sessionStorage.setItem('results', response);
					this.router.navigate(['/results']);
					this.isLoading = false;
				},
				error: (error) => {
					this.snackBar.open(JSON.parse(error['error'])['message'], 'Close', {
						duration: 5000, // Snackbar will remain open for 5 seconds
						horizontalPosition: 'center',
						verticalPosition: 'top',
					});
					this.isLoading = false;
				},
				complete: () => {
					console.log('Home Form Handling Completed.');
				},
			});
			console.log('Form Submitted!', this.homeForm.value);
		} else {
			console.log('Form is invalid');
		}
	}

	get ip_domain() {
		return this.homeForm.get('ip_domain');
	}
}
