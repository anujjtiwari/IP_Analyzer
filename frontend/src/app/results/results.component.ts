import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ResursiveDataComponent } from '../recursive-data/recursive-data.component';
import { Router } from '@angular/router';
import { HeaderComponent } from '../header/header.component';
import { LoaderComponent } from '../loader/loader.component';

@Component({
	selector: 'app-results',
	standalone: true,
	imports: [CommonModule, ResursiveDataComponent, HeaderComponent, LoaderComponent],
	templateUrl: './results.component.html',
	styleUrl: './results.component.css'
})

export class ResultsComponent implements OnInit {
	results: any;
	resultCategories: any[] = [];
	userName: string = "";
	isLoading = false;

	constructor(private router: Router) { }

	ngOnInit(): void {
		const storedResults = sessionStorage.getItem('results');
		if (storedResults) {
			this.results = JSON.parse(storedResults);
			this.prepareResults();
		}
	}

	prepareResults() {
		this.isLoading = true;
		const summary = this.results.results_summary;
		for (const key in summary) {

			if (summary[key] && Object.keys(summary[key]).length > 0){
				this.resultCategories.push({
					name: key,
					summary: summary[key],
					details: this.results.results[key] || {}, // Full details from results
					expanded: false
				});
			}
		}
		this.isLoading = false;
	}

	toggleExpand(category: any, cardElement: HTMLElement) {
		category.expanded = !category.expanded;

		if (category.expanded) {
			// Set maxHeight to the scrollHeight to expand the card
			// setTimeout(() => {
			// 	cardElement.style.maxHeight = cardElement.scrollHeight + "px";
			// }, 0);
	
			// Once the transition completes, set overflow-y to auto for scrolling
			// setTimeout(() => {
				// cardElement.style.overflowY = "auto";
			cardElement.classList.add('expanded');
			// }, 0); 
			// Wait for the max-height transition to complete (0.6s as per the CSS transition) here 600 ms
		} else {
			// cardElement.style.maxHeight = "0px";
			cardElement.classList.remove('expanded');
		}
	}

	navigateToHome() {
		this.isLoading = true;
		this.router.navigate(['/home'])
		this.isLoading = false;
	}
}
