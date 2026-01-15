import { ComponentFixture, TestBed } from '@angular/core/testing';

import { ResursiveDataComponent } from './recursive-data.component';

describe('ResursiveDataComponent', () => {
  let component: ResursiveDataComponent;
  let fixture: ComponentFixture<ResursiveDataComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ResursiveDataComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(ResursiveDataComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
